
from aws_minion.docker import generate_cap_add_options, generate_env_options
from textwrap import dedent
import shlex
import yaml


def generate_volume_options(app_folder: str, manifest: dict) -> str:
    """
    >>> generate_volume_options('myapp', {'filesystems': [{'mountpoint': '/tmp'}]})
    '-v /data/myapp/1:/tmp'
    """
    options = []
    i = 1
    for fs in manifest.get('filesystems', []):
        options.append('-v')
        options.append(shlex.quote('/data/{}/{}:{}'.format(app_folder, i, fs.get('mountpoint', '/data'))))
        i += 1
    return ' '.join(options)


def get_bash_script(docker_image, dns_name, manifest, env_vars, log_shipper_script, cap_add):
    init_script = dedent('''\
    #!/bin/bash
    iid=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    iid=${{iid/i-}}
    hostname {hostname}-$iid
    IP=$(ip -o -4 a show eth0 | awk '{{ print $4 }}' | cut -d/ -f 1)
    echo $IP $(hostname) >> /etc/hosts

    # TODO: Disk Setup (EC2 Instance Storage)
    if [ -b /dev/xvdb ]; then
        umount /dev/xvdb
        fdisk /dev/xvdb <<EOF
    o
    n
    p
    1


    w
    EOF
        mke2fs -F -L "aws-minion-data" -t ext4 -O ^has_journal -m 0 /dev/xvdb1
        mkdir /data
        mount /dev/xvdb1 /data
        for i in $(seq 1 9); do
            mkdir -p /data/{hostname}/$i
            chmod 777 /data/{hostname}/$i
        done
    fi

    # we assume everything is installed if the Docker executable exists
    if [ ! -x /usr/bin/docker ]; then
        # add Docker repo
        apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 36A1D7869245C8950F966E92D8576A8BA88D21E9
        echo 'deb https://get.docker.io/ubuntu docker main' > /etc/apt/sources.list.d/docker.list

        apt-get update

        apt-get install -y --no-install-recommends -o Dpkg::Options::="--force-confold" \
            apparmor lxc-docker rsyslog-gnutls
        adduser ubuntu docker
    fi

    until docker pull {docker_image}; do
        echo 'Docker pull failed, retrying..'
        sleep 3
    done
    containerId=$(docker run -d {add_linux_capabilities} {env_options} {volume_options} --net=host --name={hostname} \
        {docker_image})

    echo {log_shipper_script} > /tmp/log-shipper.sh
    bash /tmp/log-shipper.sh $containerId
    ''').format(docker_image=docker_image,
                hostname=dns_name,
                exposed_port=manifest['exposed_ports'][0],
                env_options=generate_env_options(env_vars),
                log_shipper_script=shlex.quote(log_shipper_script),
                volume_options=generate_volume_options(dns_name, manifest),
                add_linux_capabilities=generate_cap_add_options(cap_add))
    return init_script


def get_config_yaml(docker_image, dns_name, manifest, env_vars, log_shipper_script, cap_add):
    '''
    >>> get_config_yaml('foo/bar', '', {'exposed_ports': [80]}, {}, '', []).strip()
    '#zalando-ami-config\\ncapabilities_add: []\\nports: {80: 80}\\nruntime: Docker\\nsource: foo/bar'
    '''
    data = {
        'runtime': 'Docker',
        'source': docker_image,
        'ports': {port: port for port in manifest['exposed_ports']},
        'capabilities_add': cap_add
    }
    if 'root' in manifest:
        data['root'] = bool(manifest['root'])
    if env_vars:
        data['environment'] = env_vars
    return '#zalando-ami-config\n{}'.format(yaml.safe_dump(data))
