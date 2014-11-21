#!/usr/bin/env python3
import shlex
from textwrap import dedent
import boto.vpc
import boto.ec2
import boto.ec2.elb
import boto.ec2.autoscale
import boto.iam
import boto.route53
from boto.ec2.autoscale import LaunchConfiguration
from boto.ec2.autoscale import AutoScalingGroup

import boto.manage.cmdshell
from boto.ec2.elb import HealthCheck
import click
import collections
import os
import random
import time
import datetime
import re
import yaml

# Ubuntu Server 14.04 LTS (HVM), SSD Volume Type
from aws_minion.console import print_table, action, ok, error
from aws_minion.context import Context

AMI_ID = 'ami-f0b11187'

CONFIG_FILE_PATH = '~/.aws-minion.yaml'
AWS_CREDENTIALS_PATH = '~/.aws/credentials'
APPLICATION_NAME_PATTERN = re.compile('^[a-z][a-z0-9-]{,199}$')
# NOTE: version MUST not contain any dash ("-")
APPLICATION_VERSION_PATTERN = re.compile('^[a-zA-Z0-9.]{1,200}$')

VPC_ID_PATTERN = re.compile('^vpc-[a-z0-9]+$')

SecurityGroupRule = collections.namedtuple("SecurityGroupRule",
                                           ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def validate_application_name(ctx, param, value):
    match = APPLICATION_NAME_PATTERN.match(value)
    if not match:
        raise click.BadParameter('invalid application name (allowed: {})'.format(APPLICATION_NAME_PATTERN.pattern))
    return value


def validate_application_version(ctx, param, value):
    match = APPLICATION_VERSION_PATTERN.match(value)
    if not match:
        raise click.BadParameter('invalid app version (allowed: {})'.format(APPLICATION_VERSION_PATTERN.pattern))
    return value


def validate_vpc_id(ctx, param, value):
    match = VPC_ID_PATTERN.match(value)
    if not match:
        raise click.BadParameter('invalid VPC ID (allowed: {})'.format(VPC_ID_PATTERN.pattern))
    return value


class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))


def generate_random_name(prefix: str, size: int) -> str:
    """
    See GenerateRandomName in vendor/src/github.com/docker/libcontainer/utils/utils.go

    >>> len(generate_random_name('abc', 4))
    7
    """
    return '{}%0{}x'.format(prefix, size) % random.randrange(16 ** size)


def modify_sg(c, group, rule, authorize=False, revoke=False):
    src_group = None
    if rule.src_group_name:
        src_group = c.get_all_security_groups([rule.src_group_name])[0]

    if authorize and not revoke:
        group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.cidr_ip,
                        src_group=src_group)
    elif not authorize and revoke:
        group.revoke(ip_protocol=rule.ip_protocol,
                     from_port=rule.from_port,
                     to_port=rule.to_port,
                     cidr_ip=rule.cidr_ip,
                     src_group=src_group)


class ApplicationNotFound(Exception):
    def __init__(self, application_name):
        self.application_name = application_name

    def __str__(self):
        return 'Application "{}" does not exist'.format(self.application_name)


def get_app_security_group_manifest(conn, application_name: str):
    all_security_groups = conn.get_all_security_groups()
    sg_name = 'app-{}'.format(application_name)
    for _sg in all_security_groups:
        if _sg.name == sg_name:
            manifest = yaml.safe_load(_sg.tags['Manifest'])
            return _sg, manifest
    raise ApplicationNotFound(application_name)


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx):
    path = os.path.expanduser(CONFIG_FILE_PATH)
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    if not data and not 'configure'.startswith(ctx.invoked_subcommand):
        raise click.UsageError('Please run "minion configure" first.')
    ctx.obj = Context(data)


@cli.command()
@click.option('--region', help='AWS region ID', prompt='AWS region ID (e.g. "eu-west-1")')
@click.option('--vpc', help='AWS VPC ID', prompt='AWS VPC ID (e.g. "vpc-abcd1234")', callback=validate_vpc_id)
@click.option('--domain', help='DNS domain (e.g. apps.example.org)', prompt='DNS domain (e.g. apps.example.org)')
@click.pass_context
def configure(ctx, region, vpc, domain):
    """
    Configure the AWS connection settings
    """
    param_data = {'region': region, 'vpc': vpc, 'domain': domain}
    path = os.path.expanduser(CONFIG_FILE_PATH)
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    else:
        data = {}
    for k, v in param_data.items():
        if v:
            data[k] = v

    credentials_path = os.path.expanduser(AWS_CREDENTIALS_PATH)
    if not os.path.exists(credentials_path):
        click.secho('AWS credentials file not found, please provide them now')
        key_id = click.prompt('AWS Access Key ID')
        secret = click.prompt('AWS Secret Access Key', hide_input=True)

        os.makedirs(os.path.dirname(credentials_path), exist_ok=True)

        credentials_content = dedent('''\
            [default]
            aws_access_key_id     = {key_id}
            aws_secret_access_key = {secret}
            ''').format(key_id=key_id, secret=secret)
        with open(credentials_path, 'w') as fd:
            fd.write(credentials_content)

    # handle Loggly configuration if needed
    while True:
        configure_loggly = click.prompt('Do you want to configure Loggly? [y/n]', 'y')
        configure_loggly = configure_loggly.lower()
        if configure_loggly == 'y' or configure_loggly == 'n':
            break
        else:
            print('input has to be [y/n]')

    configure_loggly = configure_loggly == 'y'

    loggly_account = None
    loggly_user = None
    loggly_password = None
    loggly_auth_token = None

    if configure_loggly:
        loggly_account = click.prompt('Loggly Account/Subdomain (e.g. "mycompany")')
        loggly_user = click.prompt('Loggly User (e.g. "jdoe")')
        loggly_password = click.prompt('Loggly Password', hide_input=True)
        loggly_auth_token = click.prompt('Loggly Auth Token', hide_input=True)

    data['loggly_account'] = loggly_account
    data['loggly_user'] = loggly_user
    data['loggly_password'] = loggly_password
    data['loggly_auth_token'] = loggly_auth_token

    action('Connecting to region {region}..', **vars())
    vpc_conn = boto.vpc.connect_to_region(region)
    if not vpc_conn:
        error('FAILED')
        return
    ok()

    action('Checking VPC {vpc}..', **vars())
    subnets = vpc_conn.get_all_vpcs(vpc_ids=[vpc])
    if not subnets:
        error('FAILED')
        return
    ok()

    action('Checking domain {domain}..', **vars())
    dns_conn = boto.route53.connect_to_region(region)
    zone = dns_conn.get_zone(domain + '.')
    if not zone:
        error('FAILED')
        return
    ok()

    with open(path, 'w', encoding='utf-8') as fd:
        fd.write(yaml.dump(data))
    ctx.obj = Context(data)


@cli.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def applications(ctx):
    """
    Manage applications, list all apps
    """
    if not ctx.invoked_subcommand:
        # list apps
        region = ctx.obj.region
        vpc = ctx.obj.vpc

        conn = boto.ec2.connect_to_region(region)

        rows = []
        all_security_groups = conn.get_all_security_groups()
        for _sg in all_security_groups:
            if _sg.name.startswith('app-') and _sg.vpc_id == vpc and not _sg.name.endswith('-lb'):
                manifest = yaml.safe_load(_sg.tags['Manifest'])
                rows.append({k: str(v) for k, v in manifest.items()})
        rows.sort(key=lambda x: (x['application_name']))
        print_table('application_name team_name exposed_ports stateful'.split(), rows)


PREFIX = 'app-'


def parse_time(s: str) -> float:
    try:
        utc = datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
        return utc - time.timezone
    except:
        return None


@cli.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def versions(ctx):
    """
    Manage application versions, list all versions
    """
    if not ctx.invoked_subcommand:
        rows = []
        for version in ctx.obj.get_versions():

            lb = version.get_load_balancer()
            if lb:
                dns_name = lb.dns_name
                counter = collections.Counter(i.state for i in lb.get_instance_health())
            else:
                dns_name = ''
                counter = collections.Counter()

            instance_states = ', '.join(['{}x {}'.format(count, state) for state, count in counter.most_common(10)])

            if not instance_states:
                instance_states = '(no instances)'

            rows.append({'application_name': version.application_name,
                         'application_version': version.version,
                         'docker_image': version.docker_image,
                         'instance_states': instance_states,
                         'desired_capacity': version.auto_scaling_group.desired_capacity,
                         'dns_name': dns_name,
                         'weight': version.weight,
                         'created_time': parse_time(version.auto_scaling_group.created_time)})

        rows.sort(key=lambda x: (x['application_name'], x['application_version']))
        print_table(('application_name application_version ' +
                     'docker_image instance_states desired_capacity weight created_time').split(), rows)


def parse_instance_name(name: str) -> tuple:
    application_name, application_version = name[len(PREFIX):].rsplit('-', 1)
    return application_name, application_version


@cli.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def instances(ctx):
    """
    Manage application instances, list all instances
    """
    if not ctx.invoked_subcommand:
        rows = []
        for instance in ctx.obj.get_instances():
            application_name, application_version = parse_instance_name(instance.tags['Name'])
            rows.append({'application_name': application_name,
                         'application_version': application_version,
                         'instance_id': instance.id,
                         'team': instance.tags.get('Team', ''),
                         'ip_address': instance.ip_address,
                         'state': instance.state.upper(),
                         'launch_time': parse_time(instance.launch_time)})
        now = time.time()
        rows.sort(key=lambda x: (x['application_name'], x['application_version'], now - x['launch_time']))
        print_table('application_name application_version instance_id team ip_address state launch_time'.split(), rows)


@versions.command()
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('percentage', type=click.IntRange(0, 100, clamp=True))
@click.pass_context
def traffic(ctx, application_name, application_version, percentage: int):
    """
    Set the percentage of the traffic for a single application version
    """
    region = ctx.obj.region
    domain = ctx.obj.domain

    version = ctx.obj.get_version(application_name, application_version)

    identifier = version.dns_identifier

    dns_conn = boto.route53.connect_to_region(region)
    zone = dns_conn.get_zone(domain + '.')
    dns_name = '{}.{}.'.format(application_name, domain)

    lb = version.get_load_balancer()

    rr = zone.get_records()

    partial_count = 0
    partial_sum = 0
    known_record_weights = {}
    for r in rr:
        if r.type == 'CNAME' and r.name == dns_name:
            if r.weight:
                w = int(r.weight)
            else:
                w = 0
            known_record_weights[r.identifier] = w
            if r.identifier != identifier:
                partial_sum = partial_sum + w
                partial_count = partial_count + 1

    if identifier not in known_record_weights:
        known_record_weights[identifier] = 0

    if partial_count:
        delta = int((100 - percentage - partial_sum) / partial_count)
    else:
        delta = 0
        # TODO: show a warning
        percentage = 100

    new_record_weights = {}
    total_weight = 0
    for i, w in known_record_weights.items():
        if i == identifier:
            n = percentage
        else:
            if percentage == 100:
                n = 0
            else:
                n = int(max(1, w + delta))
        new_record_weights[i] = n
        total_weight = total_weight + n

    action('Setting weights..')
    did_the_upsert = False
    for r in rr:
        if r.type == 'CNAME' and r.name == dns_name:
            w = new_record_weights[r.identifier]
            if w:
                if int(r.weight) != w:
                    r.weight = w
                    rr.add_change_record('UPSERT', r)
                if identifier == r.identifier:
                    did_the_upsert = True
            else:
                rr.add_change_record('DELETE', r)

    if percentage > 0 and not did_the_upsert:
        change = rr.add_change('CREATE', dns_name, 'CNAME', ttl=60, identifier=identifier, weight=percentage)
        change.add_value(lb.dns_name)

    if rr.changes:
        rr.commit()
    ok()


@versions.command()
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('desired-instances', type=int)
@click.pass_context
def scale(ctx, application_name, application_version, desired_instances: int):
    """
    Scale an application version (set desired instance count)
    """

    version = ctx.obj.get_version(application_name, application_version)

    action('Scaling application {application_name} version {application_version} to {desired_instances} instances',
           **vars())

    version.auto_scaling_group.set_capacity(desired_instances)
    ok()


@versions.command('delete')
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.pass_context
def delete_version(ctx, application_name: str, application_version: str):
    """
    Delete an application version and shutdown all associated instances
    """
    region = ctx.obj.region

    conn = boto.ec2.connect_to_region(region)

    version = ctx.obj.get_version(application_name, application_version)

    autoscale = boto.ec2.autoscale.connect_to_region(region)

    running_instance_ids = set([i.instance_id for i in version.auto_scaling_group.instances])

    action('Shutting down {instance_count} instances..', instance_count=len(running_instance_ids))
    version.auto_scaling_group.shutdown_instances()

    # wait for shutdown
    while running_instance_ids:
        instances = conn.get_only_instances(instance_ids=list(running_instance_ids))
        for instance in instances:
            if instance.state.lower() == 'terminated':
                running_instance_ids.remove(instance.id)
        time.sleep(3)
        click.secho(' .', nl=False)
    ok()

    action('Deleting auto scaling group..')
    while True:
        try:
            version.auto_scaling_group.delete()
            break
        except:
            # You cannot delete an AutoScalingGroup while there are scaling activities in progress for that group.
            time.sleep(3)
            click.secho(' .', nl=False)
    ok()

    lcs = autoscale.get_all_launch_configurations(
        names=['app-{}-{}'.format(application_name, application_version)])

    for lc in lcs:
        lc.delete()

    action('Deleting load balancer..')
    elb_conn = boto.ec2.elb.connect_to_region(region)
    lbs = elb_conn.get_all_load_balancers(load_balancer_names='app-{}-{}'.format(application_name,
                                                                                 application_version.replace('.', '-')))

    for lb in lbs:
        lb.delete()
    ok()


def generate_env_options(env_vars: dict):
    """
    Generate Docker env options (-e) for a given dictionary

    >>> generate_env_options({})
    ''

    >>> generate_env_options({'a': 1})
    '-e a=1'

    >>> generate_env_options({'a': '; rm -fr'})
    "-e 'a=; rm -fr'"
    """
    options = []
    for key, value in sorted(env_vars.items()):
        options.append('-e')
        options.append(shlex.quote('{}={}'.format(key, value)))

    return ' '.join(options)


def prepare_log_shipper_script(application_name, application_version, data):
    if not data.get('loggly_auth_token'):
        return ''
    return dedent('''\
        #!/bin/bash
        LOG_FILE=/var/log/docker.log

        containerId=$1
        if [ "$containerId" = "" ]
        then
           echo "no Docker container id passed to log shipper script"
           exit 1
        fi

        currentDockerFile=/var/lib/docker/containers/$containerId/$containerId-json.log

        ln $currentDockerFile $LOG_FILE
        chmod 666 $LOG_FILE

        f=/etc/rsyslog.d/22-loggly.conf

        # Define the template used for sending logs to Loggly. Do not change this format.
        echo '$template LogglyFormat,"<%pri%>%protocol-version% %timestamp:::date-rfc3339% \
%HOSTNAME% %app-name% %procid% %msgid% [{loggly_auth_token}@41058 tag=\\"system\\"] %msg%\\n"' > $f
        echo '*.* @@logs-01.loggly.com:514;LogglyFormat' >> $f

        f=/etc/rsyslog.d/21-filemonitoring-{application_name}-{application_version}.conf
        echo '$ModLoad imfile' > $f
        echo '$InputFilePollInterval 10' >> $f
        echo '$WorkDirectory /var/spool/rsyslog' >> $f
        echo '$PrivDropToGroup adm' >> $f
        echo '$InputFileName /var/log/docker.log' >> $f
        echo '$InputFileTag {application_name}-{application_version}:' >> $f
        echo '$InputFileStateFile stat-{application_name}-{application_version}' >> $f
        echo '$InputFileSeverity info' >> $f
        echo '$InputFilePersistStateInterval 20000' >> $f
        echo '$InputRunFileMonitor' >> $f
        echo '$template LogglyFormatFile{application_name}-{application_version},"<%pri%>%protocol-version% \
%timestamp:::date-rfc3339% %HOSTNAME% %app-name% %procid% %msgid% \
[{loggly_auth_token}@41058 tag=\\"file\\"] %msg%\\n"' >> $f
        echo 'if $programname == '\\''{application_name}-{application_version}'\\'' then \
@@logs-01.loggly.com:514;LogglyFormatFile{application_name}-{application_version}' >> $f
        echo 'if $programname == '\\''{application_name}-{application_version}'\\'' then stop' >> $f

        service rsyslog restart
        ''').format(application_name=application_name,
                    application_version=application_version,
                    loggly_user=data['loggly_user'],
                    loggly_password=data['loggly_password'],
                    loggly_account=data['loggly_account'],
                    loggly_auth_token=data['loggly_auth_token'])


@versions.command('create')
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('docker-image')
@click.option('--env', '-e', multiple=True, help='Environment variable(s) to pass to "docker run"')
@click.pass_context
def create_version(ctx, application_name: str, application_version: str, docker_image: str, env: list):
    """
    Create a new application version
    """

    region = ctx.obj.region
    vpc = ctx.obj.vpc

    vpc_conn = boto.vpc.connect_to_region(region)
    subnets = vpc_conn.get_all_subnets(filters={'vpcId': [vpc]})

    conn = boto.ec2.connect_to_region(region)

    app = ctx.obj.get_application(application_name)

    sg, manifest = app.security_group, app.manifest

    env_vars = {}

    for key_value in env:
        key, value = key_value.split('=', 1)
        env_vars[key] = value

    key_name = app.identifier

    log_shipper_script = prepare_log_shipper_script(application_name, application_version, ctx.obj.config)

    init_script = '''#!/bin/bash
    # add Docker repo
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 36A1D7869245C8950F966E92D8576A8BA88D21E9
    echo 'deb https://get.docker.io/ubuntu docker main' > /etc/apt/sources.list.d/docker.list

    apt-get update

    # Docker
    apt-get install -y --no-install-recommends -o Dpkg::Options::="--force-confold" apparmor lxc-docker

    containerId=$(docker run -d {env_options} -p {exposed_port}:{exposed_port} {docker_image})

    echo {log_shipper_script} > /tmp/log-shipper.sh
    bash /tmp/log-shipper.sh $containerId
    '''.format(docker_image=docker_image,
               exposed_port=manifest['exposed_ports'][0],
               env_options=generate_env_options(env_vars),
               log_shipper_script=shlex.quote(log_shipper_script))

    autoscale = boto.ec2.autoscale.connect_to_region(region)

    vpc_info = ','.join([subnet.id for subnet in subnets])

    action('Creating launch configuration for {application_name} version {application_version}..', **vars())
    lc = LaunchConfiguration(name='app-{}-{}'.format(application_name, application_version),
                             image_id=AMI_ID,
                             key_name=key_name,
                             security_groups=[sg.id],
                             user_data=init_script.encode('utf-8'),
                             instance_type=manifest.get('instance_type', 't2.micro'),
                             instance_profile_name=app.identifier,
                             associate_public_ip_address=True)
    autoscale.create_launch_configuration(lc)
    ok()

    all_security_groups = conn.get_all_security_groups()
    lb_sg_name = 'app-{}-lb'.format(application_name)
    lb_sg = None
    for _sg in all_security_groups:
        if _sg.name == lb_sg_name:
            lb_sg = _sg

    if not lb_sg:
        raise Exception('LB security group not found')

    hc = HealthCheck(
        interval=20,
        healthy_threshold=3,
        unhealthy_threshold=5,
        target='HTTP:{}/'.format(manifest['exposed_ports'][0])
    )

    action('Creating load blanacer for {application_name} version {application_version}..', **vars())
    ports = [(80, manifest['exposed_ports'][0], 'http')]
    elb_conn = boto.ec2.elb.connect_to_region(region)
    lb = elb_conn.create_load_balancer('app-{}-{}'.format(application_name,
                                                          application_version.replace('.', '-')), zones=None,
                                       listeners=ports,
                                       subnets=[subnet.id for subnet in subnets], security_groups=[lb_sg.id])
    lb.configure_health_check(hc)
    ok()

    group_name = 'app-{}-{}'.format(application_name, application_version)

    action('Creating auto scaling group for {application_name} version {application_version}..', **vars())
    ag = AutoScalingGroup(group_name=group_name,
                          load_balancers=[
                              'app-{}-{}'.format(application_name, application_version.replace('.', '-'))],
                          availability_zones=[subnet.availability_zone for subnet in subnets],
                          launch_config=lc, min_size=0, max_size=8,
                          vpc_zone_identifier=vpc_info,
                          connection=autoscale)
    autoscale.create_auto_scaling_group(ag)

    tags = [boto.ec2.autoscale.tag.Tag(connection=autoscale, key='Name', value=group_name,
                                       resource_id=group_name,
                                       propagate_at_launch=True),
            boto.ec2.autoscale.tag.Tag(connection=autoscale, key='Team', value=manifest['team_name'],
                                       resource_id=group_name,
                                       propagate_at_launch=True),
            boto.ec2.autoscale.tag.Tag(connection=autoscale, key='DockerImage', value=docker_image,
                                       resource_id=group_name,
                                       propagate_at_launch=True)
            ]
    autoscale.create_or_update_tags(tags)

    ag.set_capacity(1)
    ok()

    click.secho('DNS name of load balancer is {}'.format(lb.dns_name), fg='blue', bold=True)

    action('Waiting for instance start and LB..')
    lb = elb_conn.get_all_load_balancers(load_balancer_names=[lb.name])[0]
    while not lb.instances:
        time.sleep(3)
        click.secho(' .', nl=False)
        lb = elb_conn.get_all_load_balancers(load_balancer_names=[lb.name])[0]
    ok()

    action('Waiting for LB members to become active..')
    while not [i.state for i in lb.get_instance_health() if i.state == 'InService']:
        time.sleep(3)
        click.secho(' .', nl=False)
    ok()


@applications.command()
@click.argument('manifest-file', type=click.File('rb'))
@click.pass_context
def create(ctx, manifest_file):
    """
    Create a new application
    """

    try:
        manifest = yaml.safe_load(manifest_file.read())
    except Exception as e:
        raise click.UsageError('Failed to parse YAML file: {}'.format(e))

    application_name = manifest['application_name']
    team_name = manifest['team_name']

    validate_application_name(ctx, 'manifest-file', application_name)

    region = ctx.obj.region
    vpc = ctx.obj.vpc

    conn = boto.ec2.connect_to_region(region)

    action('Checking whether application {application_name} exists..', **vars())
    try:
        sg, manifest = get_app_security_group_manifest(conn, application_name)
        error('ALREADY EXISTS, ABORTING')
        return
    except ApplicationNotFound:
        ok()

    sg_name = 'app-{}'.format(application_name)

    action('Creating key pair for application {application_name}..', **vars())
    key_name = sg_name
    key = conn.create_key_pair(key_name)
    key_dir = os.path.expanduser('~/.ssh')
    try:
        key.save(key_dir)
    except TypeError:
        # HACK to circumvent missing merge of https://github.com/boto/boto/pull/2758
        file_path = os.path.join(key_dir, '%s.pem' % key.name)
        if os.path.exists(file_path):
            os.unlink(file_path)
        key.material = key.material.encode('ascii')
        key.save(key_dir)
    ok()

    all_security_groups = conn.get_all_security_groups()
    exists = False
    for _sg in all_security_groups:
        if _sg.name == sg_name and _sg.vpc_id == vpc:
            exists = True
    if not exists:
        action('Creating application security group {sg_name}..', **vars())
        sg = conn.create_security_group(sg_name, 'Application security group', vpc_id=vpc)
        # HACK: add manifest as tag
        sg.add_tags({'Name': sg_name, 'Team': team_name, 'Manifest': yaml.dump(manifest)})

        rules = [
            SecurityGroupRule("tcp", 22, 22, "0.0.0.0/0", None),
            SecurityGroupRule("tcp", manifest['exposed_ports'][0], manifest['exposed_ports'][0], "0.0.0.0/0", None),
        ]

        for rule in rules:
            modify_sg(conn, sg, rule, authorize=True)
        ok()

        lb_sg_name = sg_name + '-lb'
        action('Creating LB security group {lb_sg_name}..', **vars())
        sg = conn.create_security_group(lb_sg_name, 'LB security group', vpc_id=vpc)
        # HACK: add manifest as tag
        sg.add_tags({'Name': lb_sg_name, 'Team': team_name, 'Manifest': yaml.dump(manifest)})

        rules = [
            SecurityGroupRule("tcp", 80, 80, "0.0.0.0/0", None),
            SecurityGroupRule("tcp", 443, 443, "0.0.0.0/0", None),
        ]

        for rule in rules:
            modify_sg(conn, sg, rule, authorize=True)
        ok()

    action('Creating IAM role and instance profile..')
    iam_conn = boto.iam.connect_to_region(region)
    iam_conn.create_role(sg_name)
    iam_conn.create_instance_profile(sg_name)
    iam_conn.add_role_to_instance_profile(instance_profile_name=sg_name, role_name=sg_name)
    ok()


@applications.command()
@click.argument('application-name')
@click.pass_context
def delete(ctx, application_name: str):
    """
    Delete an application
    """
    region = ctx.obj.region

    conn = boto.ec2.connect_to_region(region)
    sg, manifest = get_app_security_group_manifest(conn, application_name)

    action('Deleting security group..')
    while True:
        try:
            sg.delete()
        except:
            time.sleep(3)
            click.secho(' .', nl=False)
    ok()

    action('Deleting keypair..')
    keypair = conn.get_key_pair(sg.name)
    keypair.delete()
    ok()

    action('Deleting IAM role..')
    iam_conn = boto.iam.connect_to_region(region)
    iam_conn.remove_role_from_instance_profile(instance_profile_name=sg.name, role_name=sg.name)
    iam_conn.delete_instance_profile(sg.name)
    iam_conn.delete_role(sg.name)
    ok()

    action('Deleting LB security group..')
    all_security_groups = conn.get_all_security_groups()
    lb_sg_name = 'app-{}-lb'.format(application_name)
    for _sg in all_security_groups:
        if _sg.name == lb_sg_name:
            _sg.delete()
    ok()


def main():
    cli()


if __name__ == '__main__':
    main()
