#!/usr/bin/env python3
import boto.vpc
import boto.ec2
import boto.ec2.elb
import boto.ec2.autoscale
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
        print("Authorizing missing rule %s..." % (rule,))
        group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.cidr_ip,
                        src_group=src_group)
    elif not authorize and revoke:
        print("Revoking unexpected rule %s..." % (rule,))
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


@applications.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def versions(ctx):
    """
    Manage application versions, list all versions
    """
    if not ctx.invoked_subcommand:
        # list apps
        region = ctx.obj['region']

        conn = boto.ec2.connect_to_region(region)

        # TODO: should list auto scaling groups instead of instances
        instances = conn.get_only_instances()
        rows = []
        for instance in instances:
            if 'Name' in instance.tags and instance.tags['Name'].startswith('app-'):
                rows.append({'application_version': instance.tags['Name'], 'instance_id': instance.id,
                             'team': instance.tags.get('Team', ''), 'state': instance.state.upper()})
        print_table('application_version instance_id team state'.split(), rows)


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

    if not manifest:
        raise Exception('Application not found')

    autoscale = boto.ec2.autoscale.connect_to_region(region)
    groups = autoscale.get_all_groups(names=['app-{}-{}'.format(manifest['application_name'], application_version)])

    if not groups:
        raise Exception('Autoscaling group for application version not found')

    group = groups[0]

    print(group, group.load_balancers)
    print(group.instances)

    elb_conn = boto.ec2.elb.connect_to_region(region)

    dns_conn = boto.route53.connect_to_region(region)
    zone = dns_conn.get_zone(domain + '.')
    dns_name = '{}.{}.'.format(application_name, domain)
    rr = zone.get_records()
    print(rr)

    lb = elb_conn.get_all_load_balancers(
        load_balancer_names=['app-{}-{}'.format(application_name, application_version.replace('.', '-'))])[0]

    change = rr.add_change('UPSERT', dns_name, 'CNAME', ttl=60, weight=1)
    change.add_value(lb.dns_name)


@versions.command()
@click.argument('application-name')
@click.argument('application-version')
@click.argument('desired-instances', type=int)
@click.pass_context
def scale(ctx, application_name, application_version, desired_instances):
    """
    Scale an application version (set desired instance count)
    """
    region = ctx.obj['region']

    conn = boto.ec2.connect_to_region(region)

    sg, manifest = get_app_security_group_manifest(conn, application_name)

    autoscale = boto.ec2.autoscale.connect_to_region(region)
    groups = autoscale.get_all_groups(names=['app-{}-{}'.format(manifest['application_name'], application_version)])

    if not groups:
        raise Exception('Autoscaling group for application version not found')

    group = groups[0]

    print(group, group.load_balancers)
    group.set_capacity(desired_instances)


@versions.command('delete')
@click.argument('application-name')
@click.argument('application-version')
@click.pass_context
def delete_version(ctx, application_name, application_version):
    """
    Delete an application version and shutdown all associated instances
    """
    region = ctx.obj['region']

    conn = boto.ec2.connect_to_region(region)

    sg, manifest = get_app_security_group_manifest(conn, application_name)

    autoscale = boto.ec2.autoscale.connect_to_region(region)
    groups = autoscale.get_all_groups(names=['app-{}-{}'.format(manifest['application_name'], application_version)])

    if not groups:
        raise Exception('Autoscaling group for application version not found')

    group = groups[0]

    print([i.__dict__ for i in group.instances])
    group.shutdown_instances()

    # wait for shutdown
    while [instance for instance in group.instances if instance.lifecycle_state.lower() not in ('terminated',)]:
        print(group.instances)
        # TODO: this does not work
        group.update()
        time.sleep(3)

    group.delete()

    lcs = autoscale.get_all_launch_configurations(
        names=['app-{}-{}'.format(manifest['application_name'], application_version)])

    for lc in lcs:
        lc.delete()


@versions.command('create')
@click.argument('application-name')
@click.argument('application-version')
@click.argument('docker-image')
@click.pass_context
def create_version(ctx, application_name, application_version, docker_image):
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

    key_name = sg_name

    init_script = '''#!/bin/bash
    # add Docker repo
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 36A1D7869245C8950F966E92D8576A8BA88D21E9
    echo 'deb https://get.docker.io/ubuntu docker main' > /etc/apt/sources.list.d/docker.list

    apt-get update

    # Docker
    apt-get install -y --no-install-recommends -o Dpkg::Options::="--force-confold" apparmor lxc-docker

    docker run -d -p {exposed_port}:{exposed_port} {docker_image}
    '''.format(docker_image=docker_image, exposed_port=manifest['exposed_ports'][0])

    autoscale = boto.ec2.autoscale.connect_to_region(region)

    vpc_info = ','.join([subnet])

    lc = LaunchConfiguration(name='app-{}-{}'.format(manifest['application_name'], application_version),
                             image_id=AMI_ID,
                             key_name=key_name,
                             security_groups=[sg.id],
                             user_data=init_script.encode('utf-8'), instance_type='t2.micro',

                             associate_public_ip_address=True)
    autoscale.create_launch_configuration(lc)

    hc = HealthCheck(
        interval=20,
        healthy_threshold=3,
        unhealthy_threshold=5,
        target='HTTP:{}/'.format(manifest['exposed_ports'][0])
    )

    ports = [(manifest['exposed_ports'][0], manifest['exposed_ports'][0], 'http')]
    elb_conn = boto.ec2.elb.connect_to_region(region)
    lb = elb_conn.create_load_balancer('app-{}-{}'.format(manifest['application_name'],
                                                          application_version.replace('.', '-')), zones=None,
                                       listeners=ports,
                                       subnets=[subnet], security_groups=[sg.id])
    lb.configure_health_check(hc)

    group_name = 'app-{}-{}'.format(manifest['application_name'], application_version)

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
                                       propagate_at_launch=True)
            ]
    autoscale.create_or_update_tags(tags)

    ag.set_capacity(1)


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

    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
    vpc = subnet_obj.vpc_id

    sg_name = 'app-{}'.format(application_name)

    action('Creating key pair for application {application_name}..', **vars())
    key_name = sg_name
    key = conn.create_key_pair(key_name)
    key_dir = os.path.expanduser('~/.ssh')
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
            SecurityGroupRule("tcp", 80, 80, "0.0.0.0/0", None),
            SecurityGroupRule("tcp", 443, 443, "0.0.0.0/0", None)
        ]

        for rule in rules:
            modify_sg(conn, sg, rule, authorize=True)
        ok()


def main():
    cli()


if __name__ == '__main__':
    main()
