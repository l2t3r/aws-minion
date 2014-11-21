
import boto.ec2
from boto.ec2.elb import LoadBalancer
import yaml

IDENTIFIER_PREFIX = 'app-'


class Application:

    def __init__(self, name: str, conn):
        self.name = name
        self.security_group = None

        all_security_groups = conn.get_all_security_groups()
        sg_name = self.identifier
        for _sg in all_security_groups:
            if _sg.name == sg_name:
                self.security_group = _sg
                self.manifest = yaml.safe_load(_sg.tags['Manifest'])

        if not self.security_group:
            raise Exception('Application not found')

    @property
    def identifier(self):
        return IDENTIFIER_PREFIX + self.name


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
    def identifier(self):
        return '{}{}-{}'.format(IDENTIFIER_PREFIX, self.application_name, self.version)

    @property
    def dns_identifier(self):
        return self.identifier.replace('.', '-')

    @property
    def docker_image(self):
        return self.tags.get('DockerImage')

    def get_load_balancer(self) -> LoadBalancer:
        elb_conn = boto.ec2.elb.connect_to_region(self.region)
        try:
            lb = elb_conn.get_all_load_balancers(load_balancer_names=[self.dns_identifier])[0]
            return lb
        except:
            return None


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

        conn = boto.ec2.connect_to_region(self.region)
        app = Application(application_name, conn)
        return app

    def get_versions(self, application_name=None, application_version=None) -> list:
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
        return rows

    def get_version(self, application_name, application_version):
        versions = self.get_versions(application_name, application_version)
        if not versions:
            raise Exception('Version {application_version} of application {application_name} not found'.format(
                            **vars()))
        return versions[0]

    def get_instances(self) -> list:
        conn = boto.ec2.connect_to_region(self.region)
        instances = conn.get_only_instances()
        res = []
        for inst in instances:
            if 'Name' in inst.tags and inst.tags['Name'].startswith(IDENTIFIER_PREFIX) and inst.vpc_id == self.vpc:
                res.append(ApplicationInstance(inst))
        return res
