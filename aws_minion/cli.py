#!/usr/bin/env python3
from distutils.version import LooseVersion
import shlex
from textwrap import dedent
import collections
import os
import random
import time
import datetime
import re
from xml.etree import ElementTree
import boto.vpc
import boto.ec2
import boto.ec2.elb
import boto.ec2.autoscale
import boto.iam
import boto.route53
import boto.sts
from boto.ec2.autoscale import LaunchConfiguration
from boto.ec2.autoscale import AutoScalingGroup
import boto.manage.cmdshell
from boto.ec2.elb import HealthCheck
import botocore.session
from bs4 import BeautifulSoup
import click
import keyring
import requests
import yaml
from boto.manage.cmdshell import sshclient_from_instance
import codecs

from aws_minion.console import print_table, action, ok, error, warning, choice
from aws_minion.context import Context, ApplicationNotFound
from aws_minion.utils import FloatRange

# FIXME: hardcoded for eu-west-1: Ubuntu Server 14.04 LTS (HVM), SSD Volume Type
AMI_ID = 'ami-f0b11187'

CONFIG_DIR_PATH = click.get_app_dir('aws-minion')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'aws-minion.yaml')
AWS_CREDENTIALS_PATH = '~/.aws/credentials'
APPLICATION_NAME_PATTERN = re.compile('^[a-z][a-z0-9-]{,199}$')
# NOTE: version MUST not contain any dash ("-")
APPLICATION_VERSION_PATTERN = re.compile('^[a-zA-Z0-9.]{1,200}$')

VPC_ID_PATTERN = re.compile('^vpc-[a-z0-9]+$')

PERCENT_RESOLUTION = 2
FULL_PERCENTAGE = PERCENT_RESOLUTION * 100

SecurityGroupRule = collections.namedtuple("SecurityGroupRule",
                                           ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

# Default instance health check configuration in AWS
HEALTH_CHECK_TIMEOUT_IN_S = 5
HEALTH_CHECK_INTERVAL_IN_S = 20
UNHEALTHY_THRESHOLD = 5
EXTRA_WAIT_TIME = 180
SLEEP_TIME_IN_S = 5

LOGGLY_SEARCH_REQUEST_TEMPLATE = 'https://{account}.loggly.com/apiv2/search' \
                                 '?q=syslog.appName:{app_identifier}&from={start}&until={until}&size={size}&order=asc'
LOGGLY_EVENTS_REQUEST_TEMPLATE = 'https://{account}.loggly.com/apiv2/events?rsid={rsid}'
LOGGLY_TAIL_START_TIME = '-5m'
LOGGLY_REQUEST_SIZE = 10000


def validate_application_name(ctx, param, value):
    """
    >>> validate_application_name(None, None, 'foo-bar')
    'foo-bar'
    """
    match = APPLICATION_NAME_PATTERN.match(value)
    if not match:
        raise click.BadParameter('invalid application name (allowed: {})'.format(APPLICATION_NAME_PATTERN.pattern))
    return value


def validate_application_version(ctx, param, value):
    """
    >>> validate_application_version(None, None, '1.0')
    '1.0'
    """
    match = APPLICATION_VERSION_PATTERN.match(value)
    if not match:
        raise click.BadParameter('invalid app version (allowed: {})'.format(APPLICATION_VERSION_PATTERN.pattern))
    return value


def validate_vpc_id(ctx, param, value):
    """
    >>> validate_vpc_id(None, None, 'vpc-abc123')
    'vpc-abc123'
    """
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


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('--config-file', '-c', help='Use alternative configuration file', default=CONFIG_FILE_PATH)
@click.pass_context
def cli(ctx, config_file):
    path = os.path.expanduser(config_file)
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)

    if not data and not 'configure'.startswith(ctx.invoked_subcommand):
        raise click.UsageError('Please run "minion configure" first.')
    ctx.obj = Context(data)


def write_aws_credentials(key_id, secret, session_token=None):
    credentials_path = os.path.expanduser(AWS_CREDENTIALS_PATH)
    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
    credentials_content = dedent('''\
            [default]
            aws_access_key_id     = {key_id}
            aws_secret_access_key = {secret}
            ''').format(key_id=key_id, secret=secret)
    if session_token:
        # apparently the different AWS SDKs either use "session_token" or "security_token", so set both
        credentials_content += 'aws_session_token = {}\n'.format(session_token)
        credentials_content += 'aws_security_token = {}\n'.format(session_token)
    with open(credentials_path, 'w') as fd:
        fd.write(credentials_content)


def ensure_aws_credentials():
    credentials_path = os.path.expanduser(AWS_CREDENTIALS_PATH)
    if not os.path.exists(credentials_path):
        click.secho('AWS credentials file not found, please provide them now')
        key_id = click.prompt('AWS Access Key ID')
        secret = click.prompt('AWS Secret Access Key', hide_input=True)
        write_aws_credentials(key_id, secret)


@cli.command()
@click.option('--region', help='AWS region ID')
@click.option('--vpc', help='AWS VPC ID')
@click.option('--domain', help='DNS domain')
@click.option('--ssl-certificate-arn', help='SSL certificate ARN')
@click.option('--loggly-account', help='Loggly account/subdomain')
@click.option('--loggly-user', help='Loggly username')
@click.option('--loggly-password', help='Loggly password')
@click.option('--loggly-auth-token', help='Loggly auth token')
@click.pass_context
def configure(ctx, region, vpc, domain, ssl_certificate_arn, loggly_account, loggly_user, loggly_password,
              loggly_auth_token):
    """
    Configure the AWS and Loggly connection settings
    """
    ensure_aws_credentials()

    # load config file
    os.makedirs(CONFIG_DIR_PATH, exist_ok=True)
    if os.path.exists(CONFIG_FILE_PATH):
        with open(CONFIG_FILE_PATH, 'rb') as fd:
            data = yaml.safe_load(fd)
    else:
        data = {}

    param_data = {'region': region,
                  'vpc': vpc,
                  'domain': domain,
                  'ssl_certificate_arn': ssl_certificate_arn,
                  'loggly_account': loggly_account,
                  'loggly_user': loggly_user,
                  'loggly_password': loggly_password,
                  'loggly_auth_token': loggly_auth_token}

    def ask(msg: str, name: str, suggestion: str=None, callback=None, abort=True, hide_input=False, show_default=True):
        if param_data.get(name):
            # if parameter provided, override existing value in the config file
            param_value = param_data[name].strip()
            click.echo('{}: {}'.format(msg, param_value))
        else:
            param_value = data.get(name)
            if param_value is not None:
                param_value = param_value.strip()
            if not param_value and suggestion:
                rewritten_msg = '{} (e.g. "{}")'.format(msg, suggestion)
            elif hide_input and param_value and not show_default:
                rewritten_msg = '{} [*********]'.format(msg)
            else:
                rewritten_msg = msg
            param_value = click.prompt(rewritten_msg,
                                       default=param_value,
                                       hide_input=hide_input,
                                       show_default=show_default).strip()
            if abort and param_value is None:
                raise click.Abort('{} should be provided'.format(msg))

        data[name] = param_value

        if callback:
            callback(ctx, None, param_value)
        return param_value

    region = ask('AWS region ID', 'region', suggestion='eu-west-1')

    action('Connecting to region {region}..', **vars())
    vpc_conn = boto.vpc.connect_to_region(region)
    if not vpc_conn:
        error('FAILED')
        return
    ok()

    if not vpc and not data.get('vpc'):
        action('Trying to autodetect VPC..')
        vpcs = [v for v in vpc_conn.get_all_vpcs() if not v.is_default]
        if len(vpcs) == 1:
            data['vpc'] = vpcs[0].id
        ok()

    vpc = ask('AWS VPC ID', 'vpc', suggestion='vpc-abcd1234', callback=validate_vpc_id)

    action('Checking VPC {vpc}..', **vars())
    subnets = vpc_conn.get_all_vpcs(vpc_ids=[vpc])
    if not subnets:
        error('FAILED')
        return
    ok()

    if not domain and not data.get('domain'):
        action('Trying to autodetect DNS domain..')
        dns_conn = boto.route53.connect_to_region(region)
        if not dns_conn:
            error('CONNECTION FAILED')
            return
        zones = dns_conn.get_zones()
        if len(zones) == 1:
            data['domain'] = zones[0].name.rstrip('.')
        ok()

    domain = ask('DNS domain', 'domain', suggestion='apps.myorganization.org')

    action('Checking domain {domain}..', **vars())
    dns_conn = boto.route53.connect_to_region(region)
    zone = dns_conn.get_zone(domain + '.')
    if not zone:
        error('FAILED')
        return
    ok()

    if not ssl_certificate_arn and not data.get('ssl_certificate_arn'):
        action('Trying to autodetect SSL certificate..')
        temp_context = Context({'region': region, 'domain': domain})
        data['ssl_certificate_arn'] = temp_context.find_ssl_certificate_arn()
        ok()

    ask('SSL certificate ARN', 'ssl_certificate_arn', suggestion='arn:aws:iam::123:server-certificate/mycert')

    # handle Loggly configuration if needed
    configure_loggly = loggly_auth_token or click.confirm('Do you want to configure Loggly?', default=True)

    if configure_loggly:
        ask('Loggly Account/Subdomain', 'loggly_account', suggestion='myorganization')
        ask('Loggly User', 'loggly_user', suggestion='jdoe')
        ask('Loggly Password', 'loggly_password', hide_input=True, show_default=False)
        ask('Loggly Auth Token', 'loggly_auth_token', suggestion='08ac9b07-050e-4eac-99b0-af672d8d43ca',
            hide_input=True)

    with open(CONFIG_FILE_PATH, 'w', encoding='utf-8') as fd:
        fd.write(yaml.dump(data, default_flow_style=False))
    ctx.obj = Context(data)


@cli.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def applications(ctx):
    """
    Manage applications, list all apps
    """
    if not ctx.invoked_subcommand:
        rows = []
        for app in ctx.obj.get_applications():
            rows.append({k: str(v) for k, v in app.manifest.items()})
        rows.sort()
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
                         'weight': version.weight / PERCENT_RESOLUTION if version.weight else None,
                         'created_time': parse_time(version.auto_scaling_group.created_time)})

        rows.sort(key=lambda x: (x['application_name'], LooseVersion(x['application_version'])))
        print_table(('application_name application_version ' +
                     'docker_image instance_states desired_capacity weight created_time').split(), rows)


def parse_instance_name(name: str) -> tuple:
    """
    >>> parse_instance_name('app-my-app-0.1')
    ('my-app', '0.1')
    """
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
        rows.sort(key=lambda x: (x['application_name'], LooseVersion(x['application_version']), now - x['launch_time']))
        print_table('application_name application_version instance_id team ip_address state launch_time'.split(), rows)


def get_weights(dns_name, identifier, rr):
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
                partial_sum += w
                partial_count += 1
    if identifier not in known_record_weights:
        known_record_weights[identifier] = 0
    return known_record_weights, partial_count, partial_sum


def calculate_new_weights(delta, identifier, known_record_weights, percentage):
    new_record_weights = {}
    for i, w in known_record_weights.items():
        if i == identifier:
            n = percentage
        else:
            if percentage == FULL_PERCENTAGE:
                # other versions should be disabled if 100% of traffic is ordered for our version
                n = 0
            else:
                if w > 0:
                    # if old weight is not zero
                    # do not allow it to be pushed below 1
                    n = int(max(1, w + delta))
                else:
                    # this should not happen, but just in case
                    n = 0
        new_record_weights[i] = n
    return new_record_weights


def compensate(calculation_error, compensations, identifier, new_record_weights, partial_count,
               percentage, identifier_versions):
    forced_delta = None
    # distribute the error on the versions, other then the current one
    part = calculation_error / partial_count
    if part > 0:
        part = int(max(1, part))
    else:
        part = int(min(-1, part))
    # avoid changing the older version distributions
    for i in sorted(new_record_weights.keys(), key=lambda x: identifier_versions[x], reverse=True):
        if i == identifier:
            continue
        nw = new_record_weights[i] + part
        if nw <= 0:
            # do not remove the traffic from the minimal traffic versions
            continue
        new_record_weights[i] = nw
        calculation_error -= part
        compensations[i] = part
        if calculation_error == 0:
            break
    if calculation_error != 0:
        adjusted_percentage = percentage + calculation_error
        forced_delta = calculation_error
        calculation_error = 0
        warning(
            ("Changing given percentage from {} to {} " +
             "because all other versions are already getting the possible minimum traffic").format(
                percentage / PERCENT_RESOLUTION, adjusted_percentage / PERCENT_RESOLUTION))
        percentage = adjusted_percentage
        new_record_weights[identifier] = percentage
    assert calculation_error == 0
    return forced_delta, percentage


def set_new_weights(dns_name, identifier, lb, new_record_weights, percentage, rr):
    action('Setting weights for {dns_name}..', **vars())
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
    else:
        ok(' not changed')


def change_version_traffic(application_name: str, application_version: str, ctx: Context, percentage: float):
    region = ctx.region
    domain = ctx.domain

    percentage = int(percentage * PERCENT_RESOLUTION)
    version_list = ctx.get_versions(application_name)
    if not versions:
        raise click.BadParameter('Could not find any versions for application')
    identifier_versions = collections.OrderedDict(
        (av.dns_identifier, LooseVersion(av.version)) for av in version_list)
    try:
        version = next(v for v in version_list if v.version == application_version)
    except StopIteration:
        raise click.BadParameter('Could not find provided version')
    identifier = version.dns_identifier
    dns_conn = boto.route53.connect_to_region(region)
    zone = dns_conn.get_zone(domain + '.')
    dns_name = '{}.{}.'.format(application_name, domain)
    lb = version.get_load_balancer()
    rr = zone.get_records()
    known_record_weights, partial_count, partial_sum = get_weights(dns_name, identifier, rr)
    action('Calculating new weights..')
    compensations = {}
    if partial_count:
        delta = int((FULL_PERCENTAGE - percentage - partial_sum) / partial_count)
    else:
        delta = 0
        compensations[identifier] = FULL_PERCENTAGE - percentage
        percentage = int(FULL_PERCENTAGE)
    new_record_weights = calculate_new_weights(delta, identifier, known_record_weights, percentage)
    total_weight = sum(new_record_weights.values())
    calculation_error = FULL_PERCENTAGE - total_weight
    forced_delta = None
    if calculation_error:
        forced_delta, percentage = compensate(calculation_error, compensations, identifier,
                                              new_record_weights, partial_count, percentage, identifier_versions)
    ok()
    rows = [
        {
            'application_name': application_name,
            'version': str(identifier_versions[i]),
            'identifier': i,
            'old_weight': known_record_weights[i],
            'delta': delta if i != identifier else forced_delta,
            'compensation': compensations.get(i, None),
            'new_weight': new_record_weights[i],
        } for i in known_record_weights.keys()
    ]
    print_table('application_name version identifier old_weight delta compensation new_weight'.split(),
                sorted(rows, key=lambda x: identifier_versions[x['identifier']]))
    assert sum(new_record_weights.values()) == FULL_PERCENTAGE
    set_new_weights(dns_name, identifier, lb, new_record_weights, percentage, rr)


@versions.command()
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('percentage', type=FloatRange(0, 100, clamp=True))
@click.pass_context
def traffic(ctx, application_name: str, application_version: str, percentage: float):
    """
    Set the percentage of the traffic for a single application version
    """
    change_version_traffic(application_name, application_version, ctx.obj, percentage)


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

    # Disable traffic to this version
    change_version_traffic(application_name, application_version, ctx.obj, 0.0)

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

        mkdir -pv /etc/rsyslog.d/keys/ca.d
        cd /etc/rsyslog.d/keys/ca.d/
        wget https://logdog.loggly.com/media/loggly.com.crt
        wget https://certs.starfieldtech.com/repository/sf_bundle.crt
        cat {{sf_bundle.crt,loggly.com.crt}} > loggly_full.crt
        rm {{sf_bundle.crt,loggly.com.crt}}
        cd

        currentDockerFile=/var/lib/docker/containers/$containerId/$containerId-json.log

        ln $currentDockerFile $LOG_FILE
        chmod 666 $LOG_FILE

        f=/etc/rsyslog.d/22-loggly.conf

        # Define the template used for sending logs to Loggly. Do not change this format.
        (
            echo '$template LogglyFormat,"<%pri%>%protocol-version% %timestamp:::date-rfc3339% \
%HOSTNAME% %app-name% %procid% %msgid% [{loggly_auth_token}@41058 tag=\\"system\\" tag=\\"TLS\\"] %msg%\\n"'
            echo '#RsyslogGnuTLS'
            echo '$DefaultNetstreamDriverCAFile /etc/rsyslog.d/keys/ca.d/loggly_full.crt'
            echo '$ActionSendStreamDriver gtls'
            echo '$ActionSendStreamDriverMode 1'
            echo '$ActionSendStreamDriverAuthMode x509/name'
            echo '$ActionSendStreamDriverPermittedPeer *.loggly.com'
            echo '*.* @@logs-01.loggly.com:6514;LogglyFormat'
        ) > $f

        f=/etc/rsyslog.d/21-filemonitoring-{application_name}-{application_version}.conf
        (
            echo '$ModLoad imfile'
            echo '$InputFilePollInterval 10'
            echo '$WorkDirectory /var/spool/rsyslog'
            echo '$PrivDropToGroup adm'
            echo '$InputFileName /var/log/docker.log'
            echo '$InputFileTag {application_name}-{application_version}:'
            echo '$InputFileStateFile stat-{application_name}-{application_version}'
            echo '$InputFileSeverity info'
            echo '$InputFilePersistStateInterval 20000'
            echo '$InputRunFileMonitor'
            echo '$template LogglyFormatFile{application_name}-{application_version},"<%pri%>%protocol-version% \
%timestamp:::date-rfc3339% %HOSTNAME% %app-name% %procid% %msgid% \
[{loggly_auth_token}@41058 tag=\\"file\\" tag=\\"TLS\\"] %msg%\\n"'
            echo '#RsyslogGnuTLS'
            echo '$DefaultNetstreamDriverCAFile /etc/rsyslog.d/keys/ca.d/loggly_full.crt'
            echo '$ActionSendStreamDriver gtls'
            echo '$ActionSendStreamDriverMode 1'
            echo '$ActionSendStreamDriverAuthMode x509/name'
            echo '$ActionSendStreamDriverPermittedPeer *.loggly.com'
            echo 'if $programname == '\\''{application_name}-{application_version}'\\'' then \
@@logs-01.loggly.com:6514;LogglyFormatFile{application_name}-{application_version}'
            echo 'if $programname == '\\''{application_name}-{application_version}'\\'' then stop'
        ) > $f



        service rsyslog restart
        ''').format(application_name=application_name,
                    application_version=application_version,
                    loggly_auth_token=data['loggly_auth_token'])


def extract_repository_and_tag(repo_name: str):
    """
    >>> extract_repository_and_tag('foo/bar:1.0')
    ('foo/bar', '1.0')
    """
    splits = repo_name.split(':')
    if len(splits) == 2:
        return (splits[0], splits[1])
    else:
        return (repo_name, '')


def is_tag_valid(extracted):
    """
    >>> is_tag_valid(('', ))
    False
    >>> is_tag_valid(('foo/bar', '1.0'))
    True
    """
    re_tag = re.compile('[a-zA-Z0-9-_.]+')

    if len(extracted) > 1:
        return re_tag.match(extracted[1]) is not None
    else:
        return False


def is_docker_image_valid(docker_image: str):
    """
    >>> is_docker_image_valid('nginx')
    False

    >>> is_docker_image_valid('nginx:latest')
    True

    >>> is_docker_image_valid('foo/bar:1.0')
    True

    >>> is_docker_image_valid('foo.bar.example.com:2195/namespace/my_repo:1.0')
    True
    """
    parts = docker_image.split('/')
    number_of_parts = len(parts)
    extracted = extract_repository_and_tag(parts[number_of_parts - 1])

    is_valid_tag = is_tag_valid(extracted)
    if not is_valid_tag:
        return False

    re_namespace = re.compile('[a-z0-9_]+')
    re_repo_name = re.compile('[a-zA-Z0-9-_.]+')

    extracted_repo_part = extracted[0]

    if number_of_parts == 1:
        # only repository name was specified
        return re_repo_name.match(extracted_repo_part) is not None
    elif number_of_parts == 2:
        # namspace and repository were specifed (e.g. namespace/my_repo:1.0)
        is_namespace_valid = re_namespace.match(parts[0]) is not None
        is_repo_valid = re_repo_name.match(extracted_repo_part) is not None
        return is_repo_valid and is_namespace_valid
    elif number_of_parts == 3:
        # private registry, namspace and repository were specified
        # (e.g. foo.bar.example.com:2195/namespace/my_repo:1.0)
        re_registry = re.compile("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*" +
                                 "([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])(\:[0-9]+)?$")
        re_registry_ip = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" +
                                    "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\:[0-9]+)?$")

        is_registry_valid = re_registry.match(parts[0]) is not None
        if not is_registry_valid:
            is_registry_valid = re_registry_ip.match(parts[0]) is not None

        is_namespace_valid = re_namespace.match(parts[1]) is not None
        is_repo_valid = re_repo_name.match(extracted_repo_part) is not None

        return is_registry_valid and is_namespace_valid and is_repo_valid
    else:
        return False


def print_remote_file(instance, application, remote_file_path: str):
    """
    Prints out the given file located on the specified instance.

    parameters:

    instance:         target EC2 instance
    application:      coressponding application instance
    remote_file_path: path of the target file on the EC2 instance
    """
    key_file = application.get_key_file_path()
    if not os.path.exists(key_file):
        error('could not find ssh key file {}'.format(key_file))
        return

    ssh_client = sshclient_from_instance(instance,
                                         ssh_key_file=key_file,
                                         user_name='ubuntu')

    remote_file_path = shlex.quote(remote_file_path)
    status, stdout, stderr = ssh_client.run('cat {}'.format(remote_file_path))
    if status == 0:
        click.echo('see cloud-init log for analysis:')
        click.echo(codecs.decode(stdout, "unicode_escape"))
    else:
        error('could not output file "{}" on instance {} [status={}, error_msg={}]'
              .format(remote_file_path, instance.name, status, stderr))


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

    if not is_docker_image_valid(docker_image):
        error('specified docker image {} is not valid'.format(docker_image))
        return

    region = ctx.obj.region
    vpc = ctx.obj.vpc

    vpc_conn = boto.vpc.connect_to_region(region)
    subnets = vpc_conn.get_all_subnets(filters={'vpcId': [vpc]})

    app = ctx.obj.get_application(application_name)
    sg, manifest = app.security_group, app.manifest

    env_vars = {}
    for key_value in env:
        key, value = key_value.split('=', 1)
        env_vars[key] = value

    key_name = app.identifier

    log_shipper_script = prepare_log_shipper_script(application_name, application_version, ctx.obj.config)

    dns_name = 'app-{}-{}'.format(application_name, application_version.replace('.', '-'))

    init_script = '''#!/bin/bash
    iid=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    iid=${{iid/i-}}
    hostname {hostname}-$iid

    # add Docker repo
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 36A1D7869245C8950F966E92D8576A8BA88D21E9
    echo 'deb https://get.docker.io/ubuntu docker main' > /etc/apt/sources.list.d/docker.list

    apt-get update

    # Docker
    apt-get install -y --no-install-recommends -o Dpkg::Options::="--force-confold" apparmor lxc-docker rsyslog-gnutls

    containerId=$(docker run -d {env_options} --net=host {docker_image})

    echo {log_shipper_script} > /tmp/log-shipper.sh
    bash /tmp/log-shipper.sh $containerId
    '''.format(docker_image=docker_image,
               hostname=dns_name,
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

    lb_sg_name = 'app-{}-lb'.format(application_name)
    lb_sg = ctx.obj.get_security_group(lb_sg_name)

    if not lb_sg:
        raise Exception('LB security group not found')

    hc = HealthCheck(
        interval=20,
        healthy_threshold=3,
        unhealthy_threshold=5,
        target='HTTP:{}{}'.format(manifest['exposed_ports'][0], manifest.get('health_check_http_path', '/'))
    )

    action('Creating load balancer for {application_name} version {application_version}..', **vars())
    ssl_cert_arn = ctx.obj.config.get('ssl_certificate_arn')
    if ssl_cert_arn:
        ports = [(443, manifest['exposed_ports'][0], 'https', ssl_cert_arn)]
    else:
        ports = [(80, manifest['exposed_ports'][0], 'http')]
    elb_conn = boto.ec2.elb.connect_to_region(region)
    lb = elb_conn.create_load_balancer(dns_name, zones=None, listeners=ports,
                                       subnets=[subnet.id for subnet in subnets], security_groups=[lb_sg.id])
    lb.configure_health_check(hc)
    ok()

    group_name = 'app-{}-{}'.format(application_name, application_version)

    action('Creating auto scaling group for {application_name} version {application_version}..', **vars())
    ag = AutoScalingGroup(group_name=group_name,
                          load_balancers=[dns_name],
                          availability_zones=[subnet.availability_zone for subnet in subnets],
                          launch_config=lc, min_size=0, max_size=8,
                          vpc_zone_identifier=vpc_info,
                          connection=autoscale)
    try:
        autoscale.create_auto_scaling_group(ag)
    except Exception as e:
        error('A problem occurred while trying to create auto scaling group for {}: {}'
              .format(application_name, str(e)))
        action('Deleting launch configuration after failed auto scaling group creation...')
        autoscale.delete_launch_configuration(lc.name)
        ok()
        return

    def create_tag(key, value):
        return boto.ec2.autoscale.tag.Tag(connection=autoscale, key=key, value=value, resource_id=group_name,
                                          propagate_at_launch=True)

    tags = [
        create_tag('Name', group_name),
        create_tag('Team', manifest['team_name']),
        create_tag('DockerImage', docker_image)
    ]
    autoscale.create_or_update_tags(tags)

    ag.set_capacity(1)
    ok()

    click.secho('DNS name of load balancer is {}'.format(lb.dns_name), fg='blue', bold=True)

    action('Waiting for instance start and LB..')
    lb = elb_conn.get_all_load_balancers(load_balancer_names=[lb.name])[0]
    j = 0
    while not lb.instances:
        if j > 100:
            error('Max wait time for LB instances exceeded.')
            break
        time.sleep(3)
        click.secho(' .', nl=False)
        lb = elb_conn.get_all_load_balancers(load_balancer_names=[lb.name])[0]
        j += 0
    ok()

    action('Waiting for LB members to become active..')

    # calculate max number of iterations corresponding to the max time range after which AWS declares
    # a member as 'OutOfService'
    max_wait_time = EXTRA_WAIT_TIME + UNHEALTHY_THRESHOLD * (HEALTH_CHECK_TIMEOUT_IN_S + HEALTH_CHECK_INTERVAL_IN_S)
    max_iterations = (max_wait_time / SLEEP_TIME_IN_S) + 1

    j = 0
    while not [i.state for i in lb.get_instance_health() if i.state == 'InService']:
        if j == max_iterations:
            break
        time.sleep(SLEEP_TIME_IN_S)
        click.secho(' .', nl=False)
        j += 1

    if j == max_iterations:
        error('ABORTED. Default health check time to wait for members to become active has been exceeded.' +
              ' There might be a problem with your application')

        action('Trying to retrieve information for analysis...')
        instances = ctx.obj.get_instances_by_app_identifier_and_state(group_name, 'running')
        if not instances:
            error('Could not find any running instance for group {}'.format(group_name))
        else:
            instance = instances[0]  # there can only be one
            print_remote_file(instance, app, '/var/log/cloud-init-output.log')
            ok()
    else:
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
        ctx.obj.get_application(application_name)
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
    app = ctx.obj.get_application(application_name)

    sg = app.security_group

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
    lb_sg_name = 'app-{}-lb'.format(application_name)
    lb_sg = ctx.obj.get_security_group(lb_sg_name)
    lb_sg.delete()
    ok()


def send_request_to_loggly(ctx, request: str):
    app_config = ctx.obj.config

    if 'loggly_user' not in app_config:
        error('No Loggly credentials configured. Please set them via `app configure`')

    response = requests.get(request, auth=(app_config['loggly_user'], app_config['loggly_password']))

    if response.status_code == 200:
        return response.json()
    else:
        error('Request "{}" failed with status code {}'.format(request, response.status_code))
        return None


def request_loggly_logs(ctx, account: str, app_identifier: str, start: str, until: str, size):

    # request search and obtain rsid
    request = LOGGLY_SEARCH_REQUEST_TEMPLATE.format(account=account,
                                                    app_identifier=app_identifier,
                                                    start=start,
                                                    until=until,
                                                    size=size)
    response_in_json = send_request_to_loggly(ctx, request)
    if not response_in_json:
        return None

    rsid = response_in_json['rsid']['id']

    # obtain log data fetched by foregoing search request
    request = LOGGLY_EVENTS_REQUEST_TEMPLATE.format(account=account, rsid=rsid)
    return send_request_to_loggly(ctx, request)


@versions.command('logs')
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('start', default='-1h')
@click.argument('until', default='now')
@click.argument('size', default=LOGGLY_REQUEST_SIZE)
@click.pass_context
def show_version_logs(ctx, application_name: str, application_version, start, until, size):
    app_config = ctx.obj.config
    app_identifier = '{}-{}'.format(application_name, application_version)
    account = app_config['loggly_account']

    response_in_json = request_loggly_logs(ctx, account, app_identifier, start, until, size)

    # output log data
    for event in response_in_json['events']:
        click.echo(event['event']['json']['log'], nl=False)


@instances.command('logs')
@click.argument('instance-id')
@click.argument('remote-file-path')
@click.pass_context
def cat_remote_file(ctx, instance_id: str, remote_file_path: str):
    instance = ctx.obj.get_instance_by_id(instance_id)
    if instance is None:
        error('Could not find instance with id "{}"'.format(instance_id))
        return

    app_name = instance.key_name.replace('app-', '', 1)
    app = ctx.obj.get_application(app_name)

    print_remote_file(instance, app, remote_file_path)


def get_saml_response(html):
    """
    Parse SAMLResponse from Shibboleth page

    >>> get_saml_response('<input name="a"/>')

    >>> get_saml_response('<body xmlns="bla"><form><input name="SAMLResponse" value="eG1s"/></form></body>')
    'xml'
    """
    soup = BeautifulSoup(html)

    for elem in soup.find_all('input', attrs={'name': 'SAMLResponse'}):
        saml_base64 = elem.get('value')
        xml = codecs.decode(saml_base64.encode('ascii'), 'base64').decode('utf-8')
        return xml


def get_role_label(role):
    """
    >>> get_role_label(('arn:aws:iam::123:saml-provider/Shibboleth', 'arn:aws:iam::123:role/Shibboleth-PowerUser'))
    'Shibboleth-PowerUser'
    """
    provider_arn, role_arn = role
    return role_arn.split('/')[-1]


@cli.command()
@click.option('--url', '-u', help='SAML identity provider URL')
@click.option('--user', '-U', prompt='Username')
@click.option('--password', '-p', help='Password')
@click.option('--role', '-r', help='Role to select (if user has multiple SAML roles)')
@click.option('--overwrite-credentials', help='Always overwrite AWS credentials file', is_flag=True)
@click.option('--print-env-vars', help='Print AWS credentials as environment variables', is_flag=True)
@click.pass_context
def login(ctx, url, user, password, role, overwrite_credentials, print_env_vars):
    """
    Login to SAML Identity Provider (shibboleth-idp) and retrieve temporary AWS credentials
    """
    url = url or ctx.obj.saml_identity_provider_url

    if not url:
        raise click.UsageError('Please specify SAML identity provider URL in config file or use "--url"')

    session = requests.Session()
    response = session.get(url)

    keyring_key = 'aws-minion.saml'
    password = password or keyring.get_password(keyring_key, user)
    if not password:
        password = click.prompt('Password', hide_input=True)

    action('Authenticating against {url}..', **vars())

    # NOTE: parameters are hardcoded for Shibboleth IDP
    data = {'j_username': user, 'j_password': password, 'submit': 'Login'}
    response2 = session.post(response.url, data=data)
    saml_xml = get_saml_response(response2.text)
    if not saml_xml:
        error('LOGIN FAILED')
        return
    ok()

    keyring.set_password(keyring_key, user, password)

    action('Checking SAML roles..')
    tree = ElementTree.fromstring(saml_xml)

    assertion = tree.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')

    roles = []
    for attribute in assertion.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute[@Name]'):
        if attribute.attrib['Name'] == 'https://aws.amazon.com/SAML/Attributes/Role':
            for val in attribute.findall('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                provider_arn, role_arn = val.text.split(',')
                roles.append((provider_arn, role_arn))

    if not roles:
        error('NO VALID ROLE FOUND')
        return
    ok()

    if len(roles) == 1:
        provider_arn, role_arn = roles[0]
    elif role:
        matching_roles = [_role for _role in roles if role in str(_role)]
        if not matching_roles or len(matching_roles) > 1:
            raise click.UsageError('Given role (--role) was not found or not unique')
        provider_arn, role_arn = matching_roles[0]
    else:
        roles.sort()
        provider_arn, role_arn = choice('Multiple roles found, please select one.',
                                        [(r, get_role_label(r)) for r in roles])

    action('Assuming role {role_label}..', role_label=get_role_label((provider_arn, role_arn)))
    saml_assertion = codecs.encode(saml_xml.encode('utf-8'), 'base64').decode('ascii').replace('\n', '')

    session = botocore.session.get_session()
    sts = session.get_service('sts')
    operation = sts.get_operation('AssumeRoleWithSAML')

    endpoint = sts.get_endpoint(ctx.obj.region)
    endpoint._signature_version = None
    http_response, response_data = operation.call(endpoint, role_arn=role_arn, principal_arn=provider_arn,
                                                  SAMLAssertion=saml_assertion)

    key_id = response_data['Credentials']['AccessKeyId']
    secret = response_data['Credentials']['SecretAccessKey']
    session_token = response_data['Credentials']['SessionToken']
    ok()

    if print_env_vars:
        # different AWS SDKs expect either AWS_SESSION_TOKEN or AWS_SECURITY_TOKEN, so set both
        click.secho(dedent('''\
        # environment variables with temporary AWS credentials:
        export AWS_ACCESS_KEY_ID="{key_id}"
        export AWS_SECRET_ACCESS_KEY="{secret}"
        export AWS_SESSION_TOKEN="{session_token}")
        export AWS_SECURITY_TOKEN="{session_token}"''').format(**vars()), fg='blue')

    proceed = overwrite_credentials or click.confirm('Do you want to overwrite your AWS credentials ' +
                                                     'file with the new temporary access key?', default=True)

    if proceed:
        action('Writing temporary AWS credentials..')
        write_aws_credentials(key_id, secret, session_token)
        ok()


@versions.command('tail')
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('start', default=LOGGLY_TAIL_START_TIME)
@click.argument('log-request-size', default=LOGGLY_REQUEST_SIZE)
@click.pass_context
def tail_version_logs(ctx, application_name: str, application_version, start, log_request_size):
    app_config = ctx.obj.config
    app_identifier = '{}-{}'.format(application_name, application_version)
    account = app_config['loggly_account']

    recent_event_ids = set()
    last_timestamp = 0
    while True:
        response_in_json = request_loggly_logs(ctx, account, app_identifier, start, 'now', log_request_size)

        # Given start time might be far in the past. All following requests do not need
        # to be that far in the past
        start = LOGGLY_TAIL_START_TIME

        for event in response_in_json['events']:
            timestamp = event['timestamp']
            event_id = event['id']
            # NOTE: different events can have the same timestamp
            if timestamp >= last_timestamp and event_id not in recent_event_ids:
                if len(recent_event_ids) >= log_request_size:
                    recent_event_ids.clear()
                recent_event_ids.add(event_id)
                last_timestamp = timestamp
            else:
                break

            event_data = event['event']
            if 'json' in event_data:
                event_data = event_data['json']
                if 'log' in event_data:
                    click.echo(event_data['log'], nl=False)

        time.sleep(1)


def main():
    cli()


if __name__ == '__main__':
    main()
