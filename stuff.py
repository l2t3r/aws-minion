#!/usr/bin/env python3
import boto.ec2
import boto.manage.cmdshell
from boto.manage.cmdshell import FakeServer, SSHClient
import collections
import os
import random
import time

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

conn = boto.ec2.connect_to_region('eu-central-1')
sg_name = generate_random_name('hjacobs-', 6)
key_name = sg_name
key = conn.create_key_pair(key_name)
key_dir = os.path.expanduser('~/.ssh')
key.save(key_dir)
sg = conn.create_security_group(sg_name, 'Some test group created by hjacobs', vpc_id='vpc-c649acaf')
modify_sg(conn, sg, SecurityGroupRule("tcp", 22, 22, "0.0.0.0/0", None), authorize=True)

interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id='subnet-72babe0a',
                                                                            groups=[sg.id],                                                                                                                                                associate_public_ip_address=True)
interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)

reservation = conn.run_instances('ami-b83c0aa5', instance_type='t2.micro', network_interfaces=interfaces, key_name=key_name)
instance = reservation.instances[0]
instance.add_tags({'Name': 'hjacobs-test-stuff'})

# Check up on its status every so often
status = instance.update()
while status == 'pending':
    time.sleep(10)
    status = instance.update()

print('Instance status: ' + status)
print(instance.public_dns_name)


key_extension = '.pem'
login_user = 'ubuntu'
key_path = os.path.join(os.path.expanduser(key_dir),
                                key_name+key_extension)
s = FakeServer(instance, key_path)
# HACK: we do not have public DNS...
s.hostname = instance.ip_address
print(s.ssh_key_file)
cmd = SSHClient(s, os.path.expanduser('~/.ssh/known_hosts'), login_user)
res = cmd.run('uptime')
print(res)

