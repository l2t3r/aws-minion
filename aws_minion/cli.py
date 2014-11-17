#!/usr/bin/env python3
import boto.vpc
import boto.ec2
import boto.ec2.elb
import boto.manage.cmdshell
from boto.manage.cmdshell import FakeServer, SSHClient
from boto.ec2.elb import HealthCheck
import click
import collections
import os
import random
import time

# Ubuntu Server 14.04 LTS (HVM), SSD Volume Type
AMI_ID = 'ami-f0b11187'

SecurityGroupRule = collections.namedtuple("SecurityGroupRule", ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])

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
        src_group = c.get_all_security_groups([rule.src_group_name,])[0]

    if authorize and not revoke:
        print("Authorizing missing rule %s..."%(rule,))
        group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.cidr_ip,
                        src_group=src_group)
    elif not authorize and revoke:
        print("Revoking unexpected rule %s..."%(rule,))
        group.revoke(ip_protocol=rule.ip_protocol,
                     from_port=rule.from_port,
                     to_port=rule.to_port,
                     cidr_ip=rule.cidr_ip,
                     src_group=src_group)

@click.command()
@click.option('--region')
@click.option('--subnet')
@click.option('--user')
def cli(region, subnet, user):
    vpc_conn = boto.vpc.connect_to_region(region)
    subnet_obj = vpc_conn.get_all_subnets(subnet_ids=[subnet])[0]
    vpc = subnet_obj.vpc_id

    conn = boto.ec2.connect_to_region(region)

    for instance in conn.get_only_instances():
        if 'Name' in instance.tags and instance.tags['Name'].startswith(user + '-'):
            print('Terminating', instance.id, instance.tags)
            instance.terminate()

    sg_name = generate_random_name(user + '-', 6)
    key_name = sg_name
    key = conn.create_key_pair(key_name)
    key_dir = os.path.expanduser('~/.ssh')
    key.save(key_dir)
    sg = conn.create_security_group(sg_name, 'Some test group created by ' + user, vpc_id=vpc)

    rules = [
        SecurityGroupRule("tcp", 22, 22, "0.0.0.0/0", None),
        SecurityGroupRule("tcp", 80, 80, "0.0.0.0/0", None),
    ]

    for rule in rules:
        modify_sg(conn, sg, rule, authorize=True)

    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id=subnet,
                                                                                groups=[sg.id],                                                                                                                                                associate_public_ip_address=True)
    interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)

    init_script = b'''#!/bin/bash

    # use the latest HAProxy with IPv6 support
    add-apt-repository -y ppa:vbernat/haproxy-1.5

    # add Docker repo
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 36A1D7869245C8950F966E92D8576A8BA88D21E9
    echo 'deb https://get.docker.io/ubuntu docker main' > /etc/apt/sources.list.d/docker.list

    apt-get update

    #vim editor (only temporarily for test setup)
    apt-get install vim -y

    # system utilities (only temporarily for test setup)
    apt-get install -y strace tcpdump

    # HAProxy
    mkdir -p /fakepath
    ln -fs /bin/true /fakepath/invoke-rc.d
    PATH=/fakepath:$PATH apt-get install -o Dpkg::Options::="--force-confold" --force-yes -y haproxy

    # Docker
    apt-get install -y --no-install-recommends -o Dpkg::Options::="--force-confold" apparmor lxc-docker

    # brctl
    apt-get install -y --no-install-recommends bridge-utils

    # Python
    apt-get install -y --no-install-recommends python3-all python3-pip python3-dev python3-setuptools
    apt-get install -y --no-install-recommends gcc build-essential

    # stupid workaround..
    pip3 install netifaces==0.10.4

    docker run -d -p 80:80 nginx
    '''

    reservation = conn.run_instances(AMI_ID, instance_type='t2.micro', network_interfaces=interfaces, key_name=key_name, user_data=init_script)
    instance = reservation.instances[0]
    instance.add_tags({'Name': key_name})

    time.sleep(3)

    # Check up on its status every so often
    status = instance.update()
    while status == 'pending':
        time.sleep(3)
        status = instance.update()

    print('Instance status: ' + status)
    print(instance.id)


    key_extension = '.pem'
    login_user = 'ubuntu'
    key_path = os.path.join(os.path.expanduser(key_dir),
                                    key_name+key_extension)
    s = FakeServer(instance, key_path)
    # HACK: we do not have public DNS...
    while True:
        if instance.ip_address and len(instance.ip_address) > 4:
            s.hostname = instance.ip_address
            break
        print('Waiting for IP address..')
        instance = conn.get_only_instances(instance_ids=[instance.id])[0]
        time.sleep(3)
    print('ssh -i {} ubuntu@{}'.format(s.ssh_key_file, s.hostname))
    cmd = SSHClient(s, os.path.expanduser('~/.ssh/known_hosts'), login_user)
    res = cmd.run('uptime')
    print(res)

    hc = HealthCheck(
            interval=20,
            healthy_threshold=3,
            unhealthy_threshold=5,
            target='HTTP:80/'
        )

    ports = [(80, 80, 'http')]
    elb_conn = boto.ec2.elb.connect_to_region(region)
    lb = elb_conn.create_load_balancer(key_name, zones=None, listeners=ports, subnets=[subnet], security_groups=[sg.id])
    lb.configure_health_check(hc)
    lb.register_instances([instance.id])

def main():
    cli()

if __name__ == '__main__':
    main()
