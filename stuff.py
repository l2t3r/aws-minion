#!/usr/bin/env python3
import boto.ec2
import random
import time

def generate_random_name(prefix: str, size: int) -> str:
    """
    See GenerateRandomName in vendor/src/github.com/docker/libcontainer/utils/utils.go

    >>> len(generate_random_name('abc', 4))
    7
    """
    return '{}%0{}x'.format(prefix, size) % random.randrange(16 ** size)


conn = boto.ec2.connect_to_region('eu-central-1')
sg_name = generate_random_name('hjacobs-', 6)
sg = conn.create_security_group(sg_name, 'Some test group created by hjacobs', vpc_id='vpc-c649acaf')

interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id='subnet-72babe0a',
                                                                            groups=[sg.id],                                                                                                                                                associate_public_ip_address=True)
interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)

reservation = conn.run_instances('ami-b83c0aa5', instance_type='t2.micro', network_interfaces=interfaces)
instance = reservation.instances[0]
instance.add_tags({'Name': 'hjacobs-test-stuff'})

# Check up on its status every so often
status = instance.update()
while status == 'pending':
    time.sleep(10)
    status = instance.update()

print('Instance status: ' + status)
