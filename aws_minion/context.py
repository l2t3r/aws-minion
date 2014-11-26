from distutils.version import LooseVersion
import boto.ec2
import boto.iam
from boto.ec2.elb import LoadBalancer
import functools
import yaml
import os

IDENTIFIER_PREFIX = 'app-'


class ApplicationNotFound(Exception):
    def __init__(self, application_name):
        self.application_name = application_name

    def __str__(self):
        return 'Application "{}" does not exist'.format(self.application_name)


class Application:

    def __init__(self, name: str, security_group):
        self.name = name
        self.security_group = security_group
        self.manifest = yaml.safe_load(security_group.tags['Manifest'])

    @property
    def identifier(self) -> str:
        return IDENTIFIER_PREFIX + self.name

    def get_key_file_path(self):
        """
        Constructs the path to the application's (or rather to the instances running the application)
        SSH key file which was created in `configure`
        """
        key_dir = os.path.expanduser('~/.ssh')
        return os.path.join(key_dir, '{}.pem'.format(self.identifier))


@functools.total_ordering
class ApplicationVersion:

    def __init__(self, region: str, application_name: str, version: str, auto_scaling_group):
        self.region = region
        self.application_name = application_name
        self.version = version
        self.auto_scaling_group = auto_scaling_group
        self.weight = None

        self.tags = {}
        for tag in auto_scaling_group.tags:
            self.tags[tag.key] = tag.value

    @property
    def identifier(self) -> str:
        return '{}{}-{}'.format(IDENTIFIER_PREFIX, self.application_name, self.version)

    @property
    def dns_identifier(self) -> str:
        return self.identifier.replace('.', '-')

    @property
    def docker_image(self) -> str:
        return self.tags.get('DockerImage')

    def get_load_balancer(self) -> LoadBalancer:
        elb_conn = boto.ec2.elb.connect_to_region(self.region)
        try:
            lb = elb_conn.get_all_load_balancers(load_balancer_names=[self.dns_identifier])[0]
            return lb
        except:
            return None

    def __lt__(self, other):
        key = lambda v: (v.application_name, LooseVersion(self.version), )
        return key(self) < key(other)

    def __eq__(self, other):
        return self.application_name == other.application_name and self.version == other.version


class ApplicationInstance:

    def __init__(self, ec2_instance):
        self.ec2_instance = ec2_instance

    def __getattr__(self, item):
        if hasattr(self.ec2_instance, item):
            return getattr(self.ec2_instance, item)
        raise AttributeError()


class Context:
    def __init__(self, config):
        self.config = config

    @property
    def region(self):
        return self.config['region']

    @property
    def vpc(self):
        return self.config['vpc']

    @property
    def domain(self):
        return self.config['domain']

    def get_application(self, application_name: str) -> Application:
        security_group = self.get_security_group(IDENTIFIER_PREFIX + application_name)
        if not security_group:
            raise ApplicationNotFound(application_name)
        app = Application(application_name, security_group)
        return app

    def get_versions(self, application_name: str=None, application_version: str=None) -> [ApplicationVersion]:
        """
        Get all versions defined for the given application_name and application_version strings.
        """
        autoscale = boto.ec2.autoscale.connect_to_region(self.region)
        groups = autoscale.get_all_groups()
        rows = []

        dns_conn = boto.route53.connect_to_region(self.region)
        zone = dns_conn.get_zone(self.domain + '.')

        rr = zone.get_records()

        weights = {}
        for r in rr:
            if r.type == 'CNAME' and r.identifier and r.weight:
                weights[r.identifier] = int(r.weight)

        for group in groups:
            if group.name.startswith(IDENTIFIER_PREFIX):
                _application_name, _application_version = group.name[len(IDENTIFIER_PREFIX):].rsplit('-', 1)
                if application_name and _application_name != application_name:
                    continue

                if application_version and _application_version != application_version:
                    continue

                version = ApplicationVersion(self.region, _application_name, _application_version, group)
                version.weight = weights.get(version.dns_identifier)
                rows.append(version)
        return sorted(rows)

    def get_version(self, application_name: str, application_version: str) -> ApplicationVersion:
        versions = self.get_versions(application_name, application_version)
        if not versions:
            raise Exception('Version {application_version} of application {application_name} not found'.format(
                            **vars()))
        return versions[0]

    def get_instances(self) -> [ApplicationInstance]:
        conn = boto.ec2.connect_to_region(self.region)
        instances = conn.get_only_instances()
        res = []
        for inst in instances:
            if 'Name' in inst.tags and inst.tags['Name'].startswith(IDENTIFIER_PREFIX) and inst.vpc_id == self.vpc:
                res.append(ApplicationInstance(inst))
        return res

    def get_instances_by_app_identifier_and_state(self, app_identifier: str, state: str) -> [ApplicationInstance]:
        return [i for i in self.get_instances() if i.state == state and i.tags['Name'] == app_identifier]

    def find_ssl_certificate_arn(self) -> str:
        iam_conn = boto.iam.connect_to_region(self.region)
        expected_cert_name = self.domain.replace('.', '-')
        response = iam_conn.list_server_certs()
        response = response['list_server_certificates_response']
        certs = response['list_server_certificates_result']['server_certificate_metadata_list']
        for cert in certs:
            if cert['server_certificate_name'] == expected_cert_name:
                return cert['arn']
        return None

    def get_security_group(self, sg_name: str):
        conn = boto.ec2.connect_to_region(self.region)
        all_security_groups = conn.get_all_security_groups()
        for _sg in all_security_groups:
            if _sg.name == sg_name:
                return _sg
