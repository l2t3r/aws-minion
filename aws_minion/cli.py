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


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('--region')
@click.option('--subnet')
@click.option('--user')
@click.pass_context
def cli(ctx, region, subnet, user):
    param_data = {'region': region, 'subnet': subnet, 'user': user}
    path = os.path.expanduser('~/.aws-minion.yaml')
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    for k, v in param_data.items():
        if v:
            data[k] = v
    with open(path, 'w', encoding='utf-8') as fd:
        fd.write(yaml.dump(data))
    ctx.obj = data


@cli.command()
@click.pass_context
def cleanup(ctx):
    """
    Terminate all running instances for the current user
    """
    region = ctx.obj['region']
    user = ctx.obj['user']

    if not user:
        raise ValueError('Missing user')

    conn = boto.ec2.connect_to_region(region)

    for instance in conn.get_only_instances():
        if 'Name' in instance.tags and instance.tags['Name'].startswith(user + '-'):
            print('Terminating', instance.id, instance.tags)
            instance.terminate()


@cli.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def applications(ctx):
    if not ctx.invoked_subcommand:
        # list apps
        region = ctx.obj['region']
        subnet = ctx.obj['subnet']
        user = ctx.obj['user']

        if not user:
            raise ValueError('Missing user')

        vpc_conn = boto.vpc.connect_to_region(region)
        subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
        vpc = subnet_obj.vpc_id

        conn = boto.ec2.connect_to_region(region)

        all_security_groups = conn.get_all_security_groups()
        for _sg in all_security_groups:
            if _sg.name.startswith('app-') and _sg.vpc_id == vpc:
                click.secho(_sg.name, bold=True)
                click.secho('{}'.format(_sg.tags['Manifest']))


@applications.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def versions(ctx):
    if not ctx.invoked_subcommand:
        # list apps
        region = ctx.obj['region']
        subnet = ctx.obj['subnet']
        user = ctx.obj['user']

        if not user:
            raise ValueError('Missing user')

        vpc_conn = boto.vpc.connect_to_region(region)
        subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
        vpc = subnet_obj.vpc_id

        conn = boto.ec2.connect_to_region(region)

        # TODO: should list auto scaling groups instead of instances
        instances = conn.get_only_instances()
        for instance in instances:
            if 'Name' in instance.tags and instance.tags['Name'].startswith('app-'):
                click.secho('{:<20}'.format(instance.tags['Name']), bold=True, nl=False)
                click.secho('{:<20}'.format(instance.id), nl=False)
                click.secho('{:<30}'.format(instance.tags.get('Team', '')), nl=False)
                click.secho('{:<20}'.format(instance.state))


@versions.command()
@click.option('--domain', help='DNS domain to use')
@click.argument('application-name')
@click.argument('application-version')
@click.pass_context
def activate(ctx, domain, application_name, application_version):
    """
    Activate a single application version (put it into the non-versioned LB)
    """
    region = ctx.obj['region']
    subnet = ctx.obj['subnet']
    user = ctx.obj['user']

    if not user:
        raise ValueError('Missing user')

    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
    vpc = subnet_obj.vpc_id

    conn = boto.ec2.connect_to_region(region)

    sg_name = 'app-{}'.format(application_name)

    all_security_groups = conn.get_all_security_groups()
    exists = False
    manifest = None
    for _sg in all_security_groups:
        if _sg.name == sg_name and _sg.vpc_id == vpc:
            print(_sg, _sg.id)
            exists = True
            manifest = yaml.safe_load(_sg.tags['Manifest'])
            sg = _sg

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
    lb = elb_conn.get_all_load_balancers(load_balancer_names=['app-{}'.format(application_name)])[0]
    lb.register_instances([i.instance_id for i in group.instances])

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
    Activate a single application version (put it into the non-versioned LB)
    """
    region = ctx.obj['region']
    subnet = ctx.obj['subnet']
    user = ctx.obj['user']

    if not user:
        raise ValueError('Missing user')

    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
    vpc = subnet_obj.vpc_id

    conn = boto.ec2.connect_to_region(region)

    sg_name = 'app-{}'.format(application_name)

    all_security_groups = conn.get_all_security_groups()
    exists = False
    manifest = None
    for _sg in all_security_groups:
        if _sg.name == sg_name and _sg.vpc_id == vpc:
            print(_sg, _sg.id)
            exists = True
            manifest = yaml.safe_load(_sg.tags['Manifest'])
            sg = _sg

    if not manifest:
        raise Exception('Application not found')

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
    region = ctx.obj['region']
    subnet = ctx.obj['subnet']
    user = ctx.obj['user']

    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
    vpc = subnet_obj.vpc_id

    conn = boto.ec2.connect_to_region(region)

    sg_name = 'app-{}'.format(application_name)

    all_security_groups = conn.get_all_security_groups()
    exists = False
    manifest = None
    for _sg in all_security_groups:
        if _sg.name == sg_name and _sg.vpc_id == vpc:
            print(_sg, _sg.id)
            exists = True
            manifest = yaml.safe_load(_sg.tags['Manifest'])
            sg = _sg

    if not manifest:
        raise Exception('Application not found')

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
    user = ctx.obj['user']

    if not user:
        raise ValueError('Missing user')

    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
    vpc = subnet_obj.vpc_id

    conn = boto.ec2.connect_to_region(region)

    sg_name = 'app-{}'.format(application_name)

    all_security_groups = conn.get_all_security_groups()
    exists = False
    for _sg in all_security_groups:
        if _sg.name == sg_name and _sg.vpc_id == vpc:
            print(_sg, _sg.id)
            exists = True
            manifest = yaml.safe_load(_sg.tags['Manifest'])
            sg = _sg
            # conn.delete_security_group(group_id=sg.id)

    if not exists:
        raise Exception('Application not found')

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

    # lb.register_instances([instance.id])


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

    print(manifest)

    application_name = manifest['application_name']
    team_name = manifest['team_name']

    region = ctx.obj['region']
    subnet = ctx.obj['subnet']
    user = ctx.obj['user']

    if not user:
        raise ValueError('Missing user')

    conn = boto.ec2.connect_to_region(region)

    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
    vpc = subnet_obj.vpc_id

    sg_name = 'app-{}'.format(application_name)
    print(sg_name)

    key_name = sg_name
    key = conn.create_key_pair(key_name)
    key_dir = os.path.expanduser('~/.ssh')
    key.save(key_dir)

    all_security_groups = conn.get_all_security_groups()
    exists = False
    for _sg in all_security_groups:
        if _sg.name == sg_name and _sg.vpc_id == vpc:
            print(_sg, _sg.id)
            exists = True
            print(yaml.safe_load(_sg.tags['Manifest']))
            sg = _sg
            # conn.delete_security_group(group_id=sg.id)
    if not exists:
        sg = conn.create_security_group(sg_name, 'Some test group created by ' + user, vpc_id=vpc)
        # HACK: add manifest as tag
        sg.add_tags({'Name': sg_name, 'Team': team_name, 'Manifest': yaml.dump(manifest)})

        rules = [
            SecurityGroupRule("tcp", 22, 22, "0.0.0.0/0", None),
            SecurityGroupRule("tcp", 80, 80, "0.0.0.0/0", None),
            SecurityGroupRule("tcp", 443, 443, "0.0.0.0/0", None)
        ]

        for rule in rules:
            modify_sg(conn, sg, rule, authorize=True)

    main_port = 80

    hc = HealthCheck(
        interval=20,
        healthy_threshold=3,
        unhealthy_threshold=5,
        target='HTTP:{}/'.format(main_port)
    )

    ports = [(main_port, main_port, 'http')]
    elb_conn = boto.ec2.elb.connect_to_region(region)
    lb = elb_conn.create_load_balancer(sg_name, zones=None, listeners=ports, subnets=[subnet], security_groups=[sg.id])
    # Boto does not support ELB tags (https://github.com/boto/boto/issues/2549)
    # lb.add_tags({'Manifest': yaml.dump(manifest)})
    lb.configure_health_check(hc)


def main():
    cli()


if __name__ == '__main__':
    main()