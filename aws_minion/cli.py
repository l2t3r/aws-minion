#!/usr/bin/env python3
import shlex
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
import yaml

# Ubuntu Server 14.04 LTS (HVM), SSD Volume Type
from aws_minion.console import print_table, action, ok, error

AMI_ID = 'ami-f0b11187'

SecurityGroupRule = collections.namedtuple("SecurityGroupRule",
                                           ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


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
    path = os.path.expanduser('~/.aws-minion.yaml')
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    if not data and not 'configure'.startswith(ctx.invoked_subcommand):
        raise click.UsageError('Please run "minion configure" first.')
    ctx.obj = data


@cli.command()
@click.option('--region', help='AWS region ID', prompt='AWS region ID (e.g. "eu-west-1")')
@click.option('--subnet', help='AWS subnet ID', prompt='AWS subnet ID')
@click.option('--domain', help='DNS domain (e.g. apps.example.org)', prompt='DNS domain (e.g. apps.example.org)')
@click.pass_context
def configure(ctx, region, subnet, domain):
    """
    Configure the AWS connection settings
    """
    param_data = {'region': region, 'subnet': subnet, 'domain': domain}
    path = os.path.expanduser('~/.aws-minion.yaml')
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    else:
        data = {}
    for k, v in param_data.items():
        if v:
            data[k] = v

    credentials_path = os.path.expanduser('~/.aws/credentials')
    if not os.path.exists(credentials_path):
        click.secho('AWS credentials file not found, please provide them now')
        key_id = click.prompt('AWS Access Key ID')
        secret = click.prompt('AWS Secret Access Key', hide_input=True)
        os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
        with open(credentials_path, 'w') as fd:
            fd.write('''[default]
aws_access_key_id = {key_id}
aws_secret_access_key = {secret}
'''.format(key_id=key_id, secret=secret))

    action('Connecting to region {region}..', **vars())
    vpc_conn = boto.vpc.connect_to_region(region)
    if not vpc_conn:
        error('FAILED')
        return
    ok()

    action('Checking subnet {subnet}..', **vars())
    subnets = vpc_conn.get_all_subnets(subnet_ids=[subnet])
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
    ctx.obj = data


@cli.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def applications(ctx):
    """
    Manage applications, list all apps
    """
    if not ctx.invoked_subcommand:
        # list apps
        region = ctx.obj['region']
        subnet = ctx.obj['subnet']

        vpc_conn = boto.vpc.connect_to_region(region)
        subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
        vpc = subnet_obj.vpc_id

        conn = boto.ec2.connect_to_region(region)

        rows = []
        all_security_groups = conn.get_all_security_groups()
        for _sg in all_security_groups:
            if _sg.name.startswith('app-') and _sg.vpc_id == vpc:
                manifest = yaml.safe_load(_sg.tags['Manifest'])
                rows.append({k: str(v) for k, v in manifest.items()})
        print_table('application_name team_name exposed_ports stateful'.split(), rows)

PREFIX = 'app-'


def parse_time(s: str) -> float:
    try:
        return datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
    except:
        return None


@applications.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def versions(ctx):
    """
    Manage application versions, list all versions
    """
    if not ctx.invoked_subcommand:
        # list apps
        region = ctx.obj['region']

        autoscale = boto.ec2.autoscale.connect_to_region(region)
        groups = autoscale.get_all_groups()
        rows = []
        for group in groups:
            if group.name.startswith(PREFIX):
                # TODO: version MUST NOT contain any dash "-"
                application_name, application_version = group.name[len(PREFIX):].rsplit('-', 1)

                tags = {}
                for tag in group.tags:
                    tags[tag.key] = tag.value

                elb_conn = boto.ec2.elb.connect_to_region(region)

                try:
                    lb = elb_conn.get_all_load_balancers(load_balancer_names=[group.name.replace('.', '-')])[0]
                    counter = collections.Counter(i.state for i in lb.get_instance_health())
                except:
                    counter = collections.Counter()

                instance_states = ', '.join(['{}x {}'.format(count, state) for state, count in counter.most_common(10)])

                if not instance_states:
                    instance_states = '(no instances)'

                rows.append({'application_name': application_name,
                             'application_version': application_version,
                             'docker_image': tags.get('DockerImage'),
                             'instance_states': instance_states,
                             'created_time': parse_time(group.created_time)})
        print_table('application_name application_version docker_image instance_states created_time'.split(), rows)


@applications.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def instances(ctx):
    """
    Manage application instances, list all instances
    """
    if not ctx.invoked_subcommand:
        # list apps
        region = ctx.obj['region']

        conn = boto.ec2.connect_to_region(region)

        instances = conn.get_only_instances()
        rows = []
        for instance in instances:
            if 'Name' in instance.tags and instance.tags['Name'].startswith('app-'):
                rows.append({'application_version': instance.tags['Name'], 'instance_id': instance.id,
                             'team': instance.tags.get('Team', ''),
                             'ip_address': instance.ip_address,
                             'state': instance.state.upper(),
                             'launch_time': parse_time(instance.launch_time)})
        print_table('application_version instance_id team ip_address state launch_time'.split(), rows)


@versions.command()
@click.argument('application-name')
@click.argument('application-version')
@click.pass_context
def activate(ctx, application_name, application_version):
    """
    Activate a single application version (put it into the non-versioned LB)
    """
    region = ctx.obj['region']
    domain = ctx.obj['domain']

    if not domain:
        raise ValueError('Missing DNS domain setting')

    conn = boto.ec2.connect_to_region(region)

    sg, manifest = get_app_security_group_manifest(conn, application_name)

    autoscale = boto.ec2.autoscale.connect_to_region(region)
    groups = autoscale.get_all_groups(names=['app-{}-{}'.format(manifest['application_name'], application_version)])

    if not groups:
        raise Exception('Autoscaling group for application version not found')

    elb_conn = boto.ec2.elb.connect_to_region(region)

    action('Add CNAME record..')
    dns_conn = boto.route53.connect_to_region(region)
    zone = dns_conn.get_zone(domain + '.')
    dns_name = '{}.{}.'.format(application_name, domain)
    rr = zone.get_records()

    lb = elb_conn.get_all_load_balancers(
        load_balancer_names=['app-{}-{}'.format(application_name, application_version.replace('.', '-'))])[0]

    change = rr.add_change('UPSERT', dns_name, 'CNAME', ttl=60, weight=1)
    change.add_value(lb.dns_name)
    rr.commit()
    ok()


@versions.command()
@click.argument('application-name')
@click.argument('application-version')
@click.argument('desired-instances', type=int)
@click.pass_context
def scale(ctx, application_name, application_version, desired_instances: int):
    """
    Scale an application version (set desired instance count)
    """
    region = ctx.obj['region']

    conn = boto.ec2.connect_to_region(region)

    sg, manifest = get_app_security_group_manifest(conn, application_name)

    action('Scaling application {application_name} version {application_version} to {desired_instances} instances',
           **vars())
    autoscale = boto.ec2.autoscale.connect_to_region(region)
    groups = autoscale.get_all_groups(names=['app-{}-{}'.format(manifest['application_name'], application_version)])

    if not groups:
        raise Exception('Autoscaling group for application version not found')

    group = groups[0]

    group.set_capacity(desired_instances)
    ok()


@versions.command('delete')
@click.argument('application-name')
@click.argument('application-version')
@click.pass_context
def delete_version(ctx, application_name: str, application_version: str):
    """
    Delete an application version and shutdown all associated instances
    """
    region = ctx.obj['region']

    conn = boto.ec2.connect_to_region(region)

    sg, manifest = get_app_security_group_manifest(conn, application_name)

    autoscale = boto.ec2.autoscale.connect_to_region(region)
    groups = autoscale.get_all_groups(names=['app-{}-{}'.format(application_name, application_version)])

    if not groups:
        raise Exception('Autoscaling group for application version not found')

    group = groups[0]

    running_instance_ids = set([i.instance_id for i in group.instances])

    action('Shutting down {instance_count} instances..', instance_count=len(running_instance_ids))
    group.shutdown_instances()

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
            group.delete()
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


@versions.command('create')
@click.argument('application-name')
@click.argument('application-version')
@click.argument('docker-image')
@click.option('--env', '-e', multiple=True, help='Environment variable(s) to pass to "docker run"')
@click.option('--log-url', help='Optional Loggly url (e.g. http://logs-01.loggly.com/inputs/MYTOK/tag/MYTAG)')
@click.pass_context
def create_version(ctx, application_name: str, application_version: str, docker_image: str, env: list, log_url: str):
    """
    Create a new application version
    """
    region = ctx.obj['region']
    subnet = ctx.obj['subnet']

    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]

    conn = boto.ec2.connect_to_region(region)

    sg_name = 'app-{}'.format(application_name)

    sg, manifest = get_app_security_group_manifest(conn, application_name)

    env_vars = {}

    for key_value in env:
        key, value = key_value.split('=', 1)
        env_vars[key] = value

    key_name = sg_name

    log_shipper_script = '''#!/usr/bin/env python3
import time, subprocess, select, glob, urllib.request, sys

if len(sys.argv) < 2:
    print('Missing LOG_URL argument.')
    sys.exit(1)

fns = glob.glob('/var/lib/docker/containers/*/*.log')
while not fns:
    time.sleep(3)
    fns = glob.glob('/var/lib/docker/containers/*/*.log')

filename = fns[0]
f = subprocess.Popen(['tail', '-F', filename], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)
while True:
    if p.poll(1):
        urllib.request.urlopen(sys.argv[1], f.stdout.readline().strip())
    time.sleep(1)
'''

    init_script = '''#!/bin/bash
    # add Docker repo
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 36A1D7869245C8950F966E92D8576A8BA88D21E9
    echo 'deb https://get.docker.io/ubuntu docker main' > /etc/apt/sources.list.d/docker.list

    apt-get update

    # Docker
    apt-get install -y --no-install-recommends -o Dpkg::Options::="--force-confold" apparmor lxc-docker

    docker run -d {env_options} -p {exposed_port}:{exposed_port} {docker_image}

    echo "{log_shipper_script}" > /tmp/log-shipper.py
    python3 /tmp/log-shipper.py {log_url}
    '''.format(docker_image=docker_image,
               exposed_port=manifest['exposed_ports'][0],
               env_options=generate_env_options(env_vars),
               log_shipper_script=log_shipper_script,
               log_url=log_url or '')

    autoscale = boto.ec2.autoscale.connect_to_region(region)

    vpc_info = ','.join([subnet])

    action('Creating launch configuration for {application_name} version {application_version}..', **vars())
    lc = LaunchConfiguration(name='app-{}-{}'.format(application_name, application_version),
                             image_id=AMI_ID,
                             key_name=key_name,
                             security_groups=[sg.id],
                             user_data=init_script.encode('utf-8'),
                             instance_type=manifest.get('instance_type', 't2.micro'),
                             instance_profile_name=sg_name,
                             associate_public_ip_address=True)
    autoscale.create_launch_configuration(lc)
    ok()

    hc = HealthCheck(
        interval=20,
        healthy_threshold=3,
        unhealthy_threshold=5,
        target='HTTP:{}/'.format(manifest['exposed_ports'][0])
    )

    action('Creating load blanacer for {application_name} version {application_version}..', **vars())
    ports = [(manifest['exposed_ports'][0], manifest['exposed_ports'][0], 'http')]
    elb_conn = boto.ec2.elb.connect_to_region(region)
    lb = elb_conn.create_load_balancer('app-{}-{}'.format(manifest['application_name'],
                                                          application_version.replace('.', '-')), zones=None,
                                       listeners=ports,
                                       subnets=[subnet], security_groups=[sg.id])
    lb.configure_health_check(hc)
    ok()

    group_name = 'app-{}-{}'.format(manifest['application_name'], application_version)

    action('Creating auto scaling group for {application_name} version {application_version}..', **vars())
    ag = AutoScalingGroup(group_name=group_name,
                          load_balancers=[
                              'app-{}-{}'.format(manifest['application_name'], application_version.replace('.', '-'))],
                          availability_zones=[subnet_obj.availability_zone],
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

    region = ctx.obj['region']
    subnet = ctx.obj['subnet']

    conn = boto.ec2.connect_to_region(region)

    action('Checking whether application {application_name} exists..', **vars())
    try:
        sg, manifest = get_app_security_group_manifest(conn, application_name)
        error('ALREADY EXISTS, ABORTING')
        return
    except ApplicationNotFound:
        ok()

    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
    vpc = subnet_obj.vpc_id

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
        action('Creating security group {sg_name}..', **vars())
        sg = conn.create_security_group(sg_name, 'Application security group', vpc_id=vpc)
        # HACK: add manifest as tag
        sg.add_tags({'Name': sg_name, 'Team': team_name, 'Manifest': yaml.dump(manifest)})

        rules = [
            SecurityGroupRule("tcp", 22, 22, "0.0.0.0/0", None),
            SecurityGroupRule("tcp", 443, 443, "0.0.0.0/0", None),
            SecurityGroupRule("tcp", manifest['exposed_ports'][0], manifest['exposed_ports'][0], "0.0.0.0/0", None),
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
    region = ctx.obj['region']

    conn = boto.ec2.connect_to_region(region)
    sg, manifest = get_app_security_group_manifest(conn, application_name)

    action('Deleting security group..')
    sg.delete()
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


def main():
    cli()


if __name__ == '__main__':
    main()
