#!/usr/bin/env python3
import shlex
import collections
import os
import time
import re
from boto.route53.record import ResourceRecordSets
from boto.exception import BotoServerError
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
import click
import sys
import yaml
from boto.manage.cmdshell import sshclient_from_instance
import codecs
import aws_minion
from aws_minion.aws import AWS_CREDENTIALS_PATH, write_aws_credentials, parse_time, format_time

from aws_minion.console import print_table, action, ok, error, warning, choice, Action, AliasedGroup
from aws_minion.context import Context, ApplicationNotFound, Application, APPLICATION_NAME_PATTERN, \
    APPLICATION_VERSION_PATTERN
from aws_minion.docker import is_docker_image_valid, extract_registry, replace_registry, \
    docker_image_exists, search_docker_images
from aws_minion.loggly import request_loggly_logs, LOGGLY_TAIL_START_TIME, LOGGLY_REQUEST_SIZE, print_if_app_log, \
    prepare_log_shipper_script
from aws_minion.saml import saml_login
from aws_minion.user_data import get_config_yaml
from aws_minion.user_data import get_bash_script
from aws_minion.utils import FloatRange, ComparableLooseVersion

# FIXME: Workaround for open GitHub PR (missing region eu-central-1): https://github.com/boto/boto/pull/2976
BOTO_ENDPOINTS = os.path.join(os.path.dirname(__file__), 'myendpoints.json')
os.environ['BOTO_ENDPOINTS'] = BOTO_ENDPOINTS

# FIXME: hardcoded for eu-west-1: Ubuntu Server 14.04 LTS (HVM), SSD Volume Type
AMI_ID = 'ami-f0b11187'

CONFIG_DIR_PATH = click.get_app_dir('aws-minion')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'aws-minion.yaml')

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


def validate_application_name(ctx, param, value):
    """
    >>> validate_application_name(None, None, 'foo-bar')
    'foo-bar'
    >>> validate_application_name(None, None, 'foo bar')
    Traceback (most recent call last):
        ...
    click.exceptions.BadParameter: invalid application name (allowed: ^[a-z][a-z0-9-]{,199}$)
    """
    match = APPLICATION_NAME_PATTERN.match(value)
    if not match:
        raise click.BadParameter('invalid application name (allowed: {})'.format(APPLICATION_NAME_PATTERN.pattern))
    return value


def validate_application_version(ctx, param, value):
    """
    >>> validate_application_version(None, None, '1.0')
    '1.0'
    >>> validate_application_version(None, None, 'foo bar')
    Traceback (most recent call last):
        ...
    click.exceptions.BadParameter: invalid app version (allowed: ^[a-zA-Z0-9.]{1,200}$)
    """
    match = APPLICATION_VERSION_PATTERN.match(value)
    if not match:
        raise click.BadParameter('invalid app version (allowed: {})'.format(APPLICATION_VERSION_PATTERN.pattern))
    return value


def validate_vpc_id(ctx, param, value):
    """
    >>> validate_vpc_id(None, None, 'vpc-abc123')
    'vpc-abc123'
    >>> validate_vpc_id(None, None, 'abc123')
    Traceback (most recent call last):
        ...
    click.exceptions.BadParameter: invalid VPC ID (allowed: ^vpc-[a-z0-9]+$)
    """
    match = VPC_ID_PATTERN.match(value)
    if not match:
        raise click.BadParameter('invalid VPC ID (allowed: {})'.format(VPC_ID_PATTERN.pattern))
    return value


def modify_sg(ctx, group, rule, authorize=False, revoke=False):
    src_group = None
    if rule.src_group_name:
        src_group = ctx.get_security_group(rule.src_group_name)

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


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('AWS Minion {}'.format(aws_minion.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('--config-file', '-c', help='Use alternative configuration file',
              default=CONFIG_FILE_PATH, metavar='PATH')
@click.option('--profile', '-p', help='Configuration profile to use', default='default', envvar='AWS_MINION_PROFILE',
              metavar='NAME')
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True)
@click.pass_context
def cli(ctx, config_file, profile):
    path = os.path.expanduser(config_file)
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)

    profile_data = data.get(profile, {})
    if not profile_data and not 'configure'.startswith(ctx.invoked_subcommand):
        raise click.UsageError(('Profile "{}" has no configuration. ' +
                                'Please run "minion configure" first.').format(profile))
    # instruct Boto to use the right AWS credentials for our profile
    os.environ['AWS_PROFILE'] = profile
    ctx.obj = Context(profile_data, profile)


def ensure_aws_credentials(profile, region):
    extra_config = {}
    credentials_path = os.path.expanduser(AWS_CREDENTIALS_PATH)
    file_exists = os.path.exists(credentials_path)
    options = ['Use existing AWS Access Key', 'Perform SAML login']
    selection = choice('AWS credentials file {}found. Use existing access key or SAML login?'.format(
                       '' if file_exists else 'not '), options)
    if 'SAML' in selection:
        region = region or click.prompt('AWS Region ID (e.g "eu-west-1")')
        url = click.prompt('SAML Identity Provider URL')
        user = click.prompt('SAML Username')
        saml_login(profile, region, url, user)
        extra_config['saml_identity_provider_url'] = url
        extra_config['saml_user'] = user
    elif not file_exists:
        key_id = click.prompt('AWS Access Key ID')
        secret = click.prompt('AWS Secret Access Key', hide_input=True)
        write_aws_credentials(profile, key_id, secret)
    return region, extra_config


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
    region, extra_config = ensure_aws_credentials(ctx.obj.profile, region)

    # load config file
    os.makedirs(CONFIG_DIR_PATH, exist_ok=True)
    if os.path.exists(CONFIG_FILE_PATH):
        with open(CONFIG_FILE_PATH, 'rb') as fd:
            all_data = yaml.safe_load(fd)
        data = all_data.get(ctx.obj.profile, {})
    else:
        data = {}

    data.update(extra_config)

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

    with Action('Connecting to region {region}..', **vars()) as act:
        vpc_conn = boto.vpc.connect_to_region(region)
        if not vpc_conn:
            act.error('FAILED')
            return

    if not vpc and not data.get('vpc'):
        with Action('Trying to autodetect VPC..'):
            vpcs = [v for v in vpc_conn.get_all_vpcs()]
            if len(vpcs) == 1:
                data['vpc'] = vpcs[0].id

    vpc = ask('AWS VPC ID', 'vpc', suggestion='vpc-abcd1234', callback=validate_vpc_id)

    with Action('Checking VPC {vpc}..', **vars()) as act:
        try:
            subnets = vpc_conn.get_all_vpcs(vpc_ids=[vpc])
        except:
            act.error('VPC NOT FOUND')
            return
        if not subnets:
            act.error('NO SUBNETS')
            return

    with Action('Trying to autodetect DNS domain..') as act:
        dns_conn = boto.route53.connect_to_region(region)
        if not dns_conn:
            act.error('CONNECTION FAILED')
            return
        zones = dns_conn.get_zones()
        domains = [zone.name.rstrip('.') for zone in zones]

    if len(domains) > 1:
        domain = choice('Which DNS domain to use?', domains)
        data['domain'] = domain
    else:
        if len(domains) == 1:
            data['domain'] = domains[0]

        domain = ask('DNS domain', 'domain', suggestion='apps.myorganization.org')

    with Action('Checking domain {domain}..', **vars()) as act:
        dns_conn = boto.route53.connect_to_region(region)
        zone = dns_conn.get_zone(domain + '.')
        if not zone:
            act.error('ZONE NOT FOUND')
            return

    with Action('Trying to autodetect SSL certificate..'):
        temp_context = Context({'region': region, 'domain': domain})
        data['ssl_certificate_arn'] = temp_context.find_ssl_certificate_arn()

    ask('SSL certificate ARN (enter "-" to skip)', 'ssl_certificate_arn',
        suggestion='arn:aws:iam::123:server-certificate/mycert')
    if len(data['ssl_certificate_arn']) < 2:
        # one character was entered (i.e. skip SSL), clear the certificate setting
        data['ssl_certificate_arn'] = None

    # handle Loggly configuration if needed
    configure_loggly = loggly_auth_token or click.confirm('Do you want to configure Loggly?', default=True)

    if configure_loggly:
        ask('Loggly Account/Subdomain', 'loggly_account', suggestion='myorganization')
        ask('Loggly User', 'loggly_user', suggestion='jdoe')
        ask('Loggly Password', 'loggly_password', hide_input=True, show_default=False)
        ask('Loggly Auth Token', 'loggly_auth_token', suggestion='08ac9b07-050e-4eac-99b0-af672d8d43ca',
            hide_input=True)

    ctx.obj = Context(data, ctx.obj.profile)
    with Action('Storing configuration in {path}..', path=CONFIG_FILE_PATH):
        ctx.obj.write_config(CONFIG_FILE_PATH)


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
            rows[-1]['created_time'] = app.created_time
            if 'filesystems' in app.manifest:
                rows[-1]['filesystems'] = ', '.join([fs['mountpoint'] for fs in app.manifest['filesystems']])
        rows.sort(key=lambda x: x.get('application_name'))
        print_table(('application_name team_name exposed_ports ' +
                     'instance_type health_check_http_path filesystems created_time').split(), rows)


PREFIX = 'app-'


@cli.command()
@click.option('--registry', help='Use custom registry', metavar='HOST:PORT')
@click.pass_obj
def images(ctx, registry):
    """
    List Docker images in private registry
    """
    registry = registry or ctx.get_vpc_config().get('registry')
    if not registry:
        raise click.UsageError('Docker registry not defined. ' +
                               'Define a registry for this VPC ("Config" tag on VPC) or use "--registry" option.')

    rows = []
    images = search_docker_images(registry, '')
    images.sort()
    for repo, tag, image in images:
        rows.append({'repository': repo, 'tag': tag, 'image': image})
    print_table('repository tag image'.split(), rows)


@cli.group(cls=AliasedGroup, invoke_without_command=True)
@click.option('-n', '--no-health-check', is_flag=True,
              help='Do not check LB instance states (this might be much faster)')
@click.pass_context
def versions(ctx, no_health_check):
    """
    Manage application versions, list all versions
    """
    if not ctx.invoked_subcommand:
        registry = ctx.obj.get_vpc_config().get('registry', '')

        rows = []
        for version in ctx.obj.get_versions():

            if no_health_check:
                instance_states = '(unknown)'
            else:
                lb = version.get_load_balancer()
                if lb:
                    counter = collections.Counter(i.state for i in lb.get_instance_health())
                else:
                    counter = collections.Counter()

                instance_states = ', '.join(['{}x {}'.format(count, state) for state, count in counter.most_common(10)])

                if not instance_states:
                    instance_states = '(no instances)'

            docker_image = version.docker_image

            if registry and docker_image.startswith(registry + '/'):
                docker_image = docker_image[len(registry)+1:]

            rows.append({'application_name': version.application_name,
                         'application_version': version.version,
                         'docker_image': docker_image,
                         'instance_states': instance_states,
                         'desired_capacity': version.auto_scaling_group.desired_capacity,
                         'weight': version.weight / PERCENT_RESOLUTION if version.weight else None,
                         'created_time': parse_time(version.auto_scaling_group.created_time)})

        rows.sort(key=lambda x: (x['application_name'], ComparableLooseVersion(x['application_version'])))
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
                         'public_ip': instance.ip_address,
                         'private_ip': instance.private_ip_address,
                         'state': instance.state.upper(),
                         'launch_time': parse_time(instance.launch_time)})
        now = time.time()
        rows.sort(key=lambda x: (x['application_name'],
                                 ComparableLooseVersion(x['application_version']), now - x['launch_time']))
        print_table(('application_name application_version instance_id team ' +
                     'public_ip private_ip state launch_time').split(), rows)


def get_weights(dns_name: str, identifier: str, rr: ResourceRecordSets) -> ({str: int}, int, int):
    """
    For the given dns_name, get the dns record weights from provided dns record set
    followed by partial count and partial weight sum.
    Here partial means without the element that we are operating now on.
    """
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
            if r.identifier != identifier and w > 0:
                # we should ignore all versions that do not get any traffic
                # not to put traffic on the disabled versions when redistributing traffic weights
                partial_sum += w
                partial_count += 1
    if identifier not in known_record_weights:
        known_record_weights[identifier] = 0
    return known_record_weights, partial_count, partial_sum


def calculate_new_weights(delta, identifier, known_record_weights, percentage):
    new_record_weights = {}
    deltas = {}
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
                    # do not touch versions that had not been getting traffic before
                    n = 0
        new_record_weights[i] = n
        deltas[i] = n - known_record_weights[i]
    return new_record_weights, deltas


def compensate(calculation_error, compensations, identifier, new_record_weights, partial_count,
               percentage, identifier_versions):
    """
    Compensate for the rounding errors as well as for the fact, that we do not allow to bring down the minimal weights
    lower then minimal possible value not to disable traffic from the minimally configured versions (1) and
    we do not allow to add any values to the already disabled versions (0).
    """
    # distribute the error on the versions, other then the current one
    assert partial_count
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
        compensations[identifier] = calculation_error
        calculation_error = 0
        warning(
            ("Changing given percentage from {} to {} " +
             "because all other versions are already getting the possible minimum traffic").format(
                percentage / PERCENT_RESOLUTION, adjusted_percentage / PERCENT_RESOLUTION))
        percentage = adjusted_percentage
        new_record_weights[identifier] = percentage
    assert calculation_error == 0
    return percentage


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
        if sum(new_record_weights.values()) == 0:
            ok(' DISABLED')
        else:
            ok()
    else:
        ok(' not changed')


def dump_traffic_changes(application_name: str,
                         identifier: str,
                         identifier_versions: {str: ComparableLooseVersion},
                         known_record_weights: {str: int},
                         new_record_weights: {str: int},
                         compensations: {str: int},
                         deltas: {str: int}
                         ):
    """
    dump changes to the traffic settings for the given versions
    """
    rows = [
        {
            'application_name': application_name,
            'version': str(identifier_versions[i]),
            'identifier': i,
            'old_weight': known_record_weights[i],
            # 'delta': (delta if new_record_weights[i] else 0 if i != identifier else forced_delta),
            'delta': deltas[i],
            'compensation': compensations.get(i),
            'new_weight': new_record_weights[i],
        } for i in known_record_weights.keys()
    ]

    full_switch = max(new_record_weights.values()) == FULL_PERCENTAGE

    for r in rows:
        d = r['delta']
        c = r['compensation']
        if full_switch and not d and c:
            d = -c
        r['delta'] = (d / PERCENT_RESOLUTION) if d else None
        r['old_weight'] /= PERCENT_RESOLUTION
        r['new_weight'] /= PERCENT_RESOLUTION
        r['compensation'] = (c / PERCENT_RESOLUTION) if c else None
        if identifier == r['identifier']:
            r['current'] = '<'

    print_table('application_name version identifier old_weight delta compensation new_weight current'.split(),
                sorted(rows, key=lambda x: identifier_versions[x['identifier']]))


def change_version_traffic(application_name: str, application_version: str, ctx: Context, percentage: float):
    region = ctx.region
    domain = ctx.domain

    version_list = ctx.get_versions(application_name)
    if not versions:
        raise click.BadParameter('Could not find any versions for application')
    identifier_versions = collections.OrderedDict(
        (av.dns_identifier, ComparableLooseVersion(av.version)) for av in version_list)
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
    percentage = int(percentage * PERCENT_RESOLUTION)
    known_record_weights, partial_count, partial_sum = get_weights(dns_name, identifier, rr)

    if partial_count == 0 and percentage == 0:
        # disable the last remaining version
        new_record_weights = {i: 0 for i in known_record_weights.keys()}
        ok(msg='DNS record "{dns_name}" will be removed from that application'.format(**vars()))
    else:
        with Action('Calculating new weights..'):
            compensations = {}
            if partial_count:
                delta = int((FULL_PERCENTAGE - percentage - partial_sum) / partial_count)
            else:
                delta = 0
                if percentage > 0:
                    # will put the only last version to full traffic percentage
                    compensations[identifier] = FULL_PERCENTAGE - percentage
                    percentage = int(FULL_PERCENTAGE)
            new_record_weights, deltas = calculate_new_weights(delta, identifier, known_record_weights, percentage)
            total_weight = sum(new_record_weights.values())
            calculation_error = FULL_PERCENTAGE - total_weight
            if calculation_error and calculation_error < FULL_PERCENTAGE:
                percentage = compensate(calculation_error, compensations, identifier,
                                        new_record_weights, partial_count, percentage, identifier_versions)
            assert sum(new_record_weights.values()) == FULL_PERCENTAGE
        dump_traffic_changes(application_name,
                             identifier,
                             identifier_versions,
                             known_record_weights,
                             new_record_weights,
                             compensations,
                             deltas)
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

    with Action('Scaling application {application_name} version {application_version} to {desired_instances} instances',
                **vars()):
        version.auto_scaling_group.set_capacity(desired_instances)


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

    with Action('Shutting down {instance_count} instances..', instance_count=len(running_instance_ids)) as act:
        version.auto_scaling_group.shutdown_instances()

        # wait for shutdown
        while running_instance_ids:
            instances = conn.get_only_instances(instance_ids=list(running_instance_ids))
            for instance in instances:
                if instance.state.lower() == 'terminated':
                    running_instance_ids.remove(instance.id)
            time.sleep(3)
            act.progress()

    with Action('Deleting auto scaling group..') as act:
        while True:
            try:
                version.auto_scaling_group.delete()
                break
            except:
                # You cannot delete an AutoScalingGroup while there are scaling activities in progress for that group.
                time.sleep(3)
                act.progress()

    lcs = autoscale.get_all_launch_configurations(
        names=['app-{}-{}'.format(application_name, application_version)])

    for lc in lcs:
        lc.delete()

    with Action('Deleting load balancer..'):
        elb_conn = boto.ec2.elb.connect_to_region(region)
        lbs = elb_conn.get_all_load_balancers(load_balancer_names=version.dns_identifier)
        for lb in lbs:
            lb.delete()


def print_remote_file(instance, application, remote_file_path: str):
    """
    Prints out the given file located on the specified instance.

    parameters:

    instance:         target EC2 instance
    application:      corresponding application instance
    remote_file_path: path of the target file on the EC2 instance
    """
    key_file = application.get_key_file_path()
    if not os.path.exists(key_file):
        error('could not find ssh key file {}'.format(key_file))
        return

    # HACK: sshclient_from_instance always uses "dns_name", but we only have public or private IPs...
    instance.dns_name = instance.ip_address or instance.private_ip_address
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


def map_subnets(subnets: list, route_tables: list) -> dict:
    """
    Map VPC subnets to layers
    """
    subnet_has_internet_gateway = {}
    for table in route_tables:
        has_internet_gateway = False
        for route in table.routes:
            if route.gateway_id and route.gateway_id.startswith('igw-'):
                has_internet_gateway = True
        for assoc in table.associations:
            subnet_has_internet_gateway[assoc.subnet_id] = has_internet_gateway
    by_layer = {'public': [], 'shared': [], 'private': []}
    for subnet in subnets:
        layer = 'private'
        if subnet_has_internet_gateway.get(subnet.id):
            layer = 'public'
        elif 'shared' in subnet.tags.get('Name').lower():
            layer = 'shared'
        by_layer[layer].append(subnet)
    return by_layer


@versions.command('create')
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('docker-image')
@click.option('--env', '-e', multiple=True, help='Environment variable(s) to pass to "docker run"', metavar='KEY=VAL')
@click.option('--cap-add', '-ca', multiple=True, help='Add Linux capabilities', metavar='CAP_TO_ADD')
@click.option('--public', is_flag=True, help='Launch instances and ELB in public subnet')
@click.option('--instance-type', help='Use custom EC2 instance type', metavar='EC2_TYPE')
@click.pass_context
def create_version(ctx, application_name: str, application_version: str, docker_image: str, env: list, cap_add: list,
                   public: bool, instance_type: str):
    """
    Create a new application version
    """

    if not is_docker_image_valid(docker_image):
        error('specified docker image {} is not valid'.format(docker_image))
        return

    region = ctx.obj.region
    vpc = ctx.obj.vpc
    domain = ctx.obj.domain

    vpc_conn = boto.vpc.connect_to_region(region)
    subnets = vpc_conn.get_all_subnets(filters={'vpcId': [vpc]})
    route_tables = vpc_conn.get_all_route_tables()
    subnets_by_layer = map_subnets(subnets, route_tables)
    vpc_config = ctx.obj.get_vpc_config()

    # create ELB in "shared" subnet by default
    elb_layer = 'public' if public else 'shared'
    # launch instances in private subnets by default
    instance_layer = 'public' if public else 'private'

    if not subnets_by_layer['public']:
        raise Exception('No public subnet available in VPC {}.'.format(vpc))

    if not subnets_by_layer[elb_layer]:
        warning('No shared subnet available, using public subnet(s) for ELB.')
        elb_layer = 'public'

    if not subnets_by_layer[instance_layer]:
        warning('No private subnet available, using public subnet(s) for instances.')
        instance_layer = 'public'

    app = ctx.obj.get_application(application_name)
    sg, manifest = app.security_group, app.manifest

    env_vars = {}
    for key_value in env:
        key, value = key_value.split('=', 1)
        env_vars[key] = value

    key_name = app.identifier

    log_shipper_script = prepare_log_shipper_script(application_name, application_version, ctx.obj.config)

    dns_name = 'app-{}-{}'.format(application_name, application_version.replace('.', '-'))
    fqdn = '{}-{}.{}'.format(application_name, application_version.replace('.', '-'), domain)

    registry = extract_registry(docker_image) or vpc_config.get('registry')

    if registry:
        with Action('Checking Docker registry {registry}..', registry=registry) as act:
            docker_image = replace_registry(docker_image, registry)
            if not docker_image_exists(docker_image):
                act.error('DOCKER IMAGE NOT FOUND')
                return

    conn = boto.ec2.connect_to_region(region)

    user_data_version = None
    ami_id = vpc_config.get('ami_id', AMI_ID)
    with Action('Checking AMI {ami_id}..', **vars()) as act:
        image = conn.get_image(ami_id)
        if isinstance(image.description, str):
            try:
                descr = yaml.safe_load(image.description)
                user_data_version = descr.get('user_data_version')
            except:
                # ignore invalid non-YAML image description
                pass

    if user_data_version:
        click.secho('Good, AMI "{}" supports user data version {}'.format(image.name, user_data_version),
                    fg='blue', bold=True)
        get_user_data = get_config_yaml
    else:
        click.secho('Found legacy/unknown AMI. Using Bash user data script.', fg='blue', bold=True)
        get_user_data = get_bash_script
    user_data = get_user_data(docker_image, dns_name, manifest, env_vars, log_shipper_script, cap_add)

    autoscale = boto.ec2.autoscale.connect_to_region(region)

    vpc_info = ','.join([subnet.id for subnet in subnets_by_layer[instance_layer]])

    with Action('Creating launch configuration for {application_name} version {application_version}..', **vars()):
        lc = LaunchConfiguration(name='app-{}-{}'.format(application_name, application_version),
                                 image_id=image.id,
                                 key_name=key_name,
                                 security_groups=[sg.id],
                                 user_data=user_data.encode('utf-8'),
                                 instance_type=manifest.get('instance_type', instance_type or 't2.micro'),
                                 instance_profile_name=app.identifier,
                                 associate_public_ip_address=(instance_layer == 'public'))
        autoscale.create_launch_configuration(lc)

    lb_sg_name = 'app-{}-lb'.format(application_name)
    lb_sg = ctx.obj.get_security_group(lb_sg_name)

    if not lb_sg:
        raise Exception('LB security group not found')

    exposed_protocol = manifest.get('exposed_protocol', 'http')
    hc_target_template = 'TCP:{port}' if exposed_protocol == 'tcp' else 'HTTP:{port}{path}'
    hc_target = hc_target_template.format(port=manifest['exposed_ports'][0],
                                          path=manifest.get('health_check_http_path', '/'))
    hc = HealthCheck(
        interval=20,
        healthy_threshold=3,
        unhealthy_threshold=5,
        target=hc_target
    )

    with Action('Creating load balancer for {application_name} version {application_version}..', **vars()):
        ssl_cert_arn = ctx.obj.config.get('ssl_certificate_arn')
        if ssl_cert_arn and exposed_protocol == 'http':
            ports = [(443, manifest['exposed_ports'][0], 'https', ssl_cert_arn)]
        elif exposed_protocol == 'http':
            ports = [(80, manifest['exposed_ports'][0], 'http')]
        else:
            ports = [(manifest['exposed_ports'][0], manifest['exposed_ports'][0], exposed_protocol)]
        elb_conn = boto.ec2.elb.connect_to_region(region)

        lb = elb_conn.create_load_balancer(dns_name, zones=None, listeners=ports,
                                           scheme='internet-facing' if elb_layer == 'public' else 'internal',
                                           subnets=[subnet.id for subnet in subnets_by_layer[elb_layer]],
                                           security_groups=[lb_sg.id])
        lb.configure_health_check(hc)

    group_name = 'app-{}-{}'.format(application_name, application_version)

    action('Creating auto scaling group for {application_name} version {application_version}..', **vars())
    ag = AutoScalingGroup(group_name=group_name,
                          load_balancers=[dns_name],
                          availability_zones=[subnet.availability_zone for subnet in subnets_by_layer[instance_layer]],
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

    with Action('Configuring DNS name {fqdn} ..', fqdn=fqdn):
        dns_conn = boto.route53.connect_to_region(region)
        zone = dns_conn.get_zone(ctx.obj.domain + '.')
        rr = zone.get_records()
        change = rr.add_change('UPSERT', fqdn, 'CNAME', ttl=60)
        change.add_value(lb.dns_name)
        rr.commit()

    with Action('Waiting for instance start and LB..') as act:
        lb = elb_conn.get_all_load_balancers(load_balancer_names=[lb.name])[0]
        j = 0
        while not lb.instances:
            if j > 100:
                error('Max wait time for LB instances exceeded.')
                break
            time.sleep(3)
            act.progress()
            lb = elb_conn.get_all_load_balancers(load_balancer_names=[lb.name])[0]
            j += 0

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
        if exposed_protocol == 'http':
            location_message = 'Application version URL is http{}://{}'.format('s' if ssl_cert_arn else '', fqdn)
        else:
            location_message = 'Application version available at {}'.format(fqdn)
        click.secho(location_message, fg='blue', bold=True)


@applications.command()
@click.argument('manifest-file', type=click.File('rb'))
@click.pass_context
def create(ctx, manifest_file):
    """
    Create a new application
    """

    try:
        manifest = Application.read_manifest(manifest_file)
    except Exception as e:
        raise click.UsageError('Failed to parse manifest file: {}'.format(e))

    application_name = manifest['application_name']
    team_name = manifest['team_name']

    validate_application_name(ctx, 'manifest-file', application_name)

    region = ctx.obj.region
    vpc = ctx.obj.vpc

    conn = boto.ec2.connect_to_region(region)

    with Action('Checking whether application {application_name} exists..', **vars()) as act:
        try:
            ctx.obj.get_application(application_name)
            act.error('ALREADY EXISTS, ABORTING')
            return
        except ApplicationNotFound:
            pass

    sg_name = 'app-{}'.format(application_name)

    with Action('Creating key pair for application {application_name}..', **vars()):
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

    with Action('Creating application security group {sg_name}..', **vars()):
        app_sg = conn.create_security_group(sg_name, 'Application security group', vpc_id=vpc)
        # HACK: add manifest as tag
        app_sg.add_tags({'Name': sg_name,
                         'Team': team_name,
                         'Manifest': yaml.dump(manifest),
                         'CreatedTime': format_time()})

        rules = [
            SecurityGroupRule("tcp", 22, 22, "0.0.0.0/0", None),
            # allow accessing all ports from within the same security group
            SecurityGroupRule("tcp", 0, 65535, None, sg_name)
        ]

        for rule in rules:
            modify_sg(ctx.obj, app_sg, rule, authorize=True)

    lb_sg_name = sg_name + '-lb'
    with Action('Creating LB security group {lb_sg_name}..', **vars()):
        sg = conn.create_security_group(lb_sg_name, 'LB security group', vpc_id=vpc)
        # HACK: add manifest as tag
        sg.add_tags({'Name': lb_sg_name, 'Team': team_name, 'Manifest': yaml.dump(manifest)})

        exposed_protocol = manifest.get('exposed_protocol', 'http')

        if exposed_protocol == 'http':
            rules = [
                SecurityGroupRule("tcp", 80, 80, "0.0.0.0/0", None),
                SecurityGroupRule("tcp", 443, 443, "0.0.0.0/0", None),
            ]
        elif exposed_protocol == 'tcp':
            exposed_port = manifest['exposed_ports'][0]
            rules = [SecurityGroupRule("tcp", exposed_port, exposed_port, "0.0.0.0/0", None)]

        for rule in rules:
            modify_sg(ctx.obj, sg, rule, authorize=True)

        # allow accessing the "exposed" application ports only from the ELB
        for port in manifest['exposed_ports']:
            modify_sg(ctx.obj, app_sg, SecurityGroupRule("tcp", port, port, None, lb_sg_name), authorize=True)

    with Action('Creating IAM role and instance profile..'):
        iam_conn = boto.iam.connect_to_region(region)
        iam_conn.create_role(sg_name)
        iam_conn.create_instance_profile(sg_name)
        iam_conn.add_role_to_instance_profile(instance_profile_name=sg_name, role_name=sg_name)


@applications.command()
@click.argument('manifest-file', type=click.File('rb'))
@click.pass_obj
def update(ctx: Context, manifest_file):
    """
    Update application manifest
    """

    try:
        manifest = Application.read_manifest(manifest_file)
    except Exception as e:
        raise click.UsageError('Failed to parse manifest file: {}'.format(e))

    application_name = manifest['application_name']
    app = ctx.get_application(application_name)

    with Action('Updating application manifest..'):
        app.update_manifest(manifest)


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

    with Action('Deleting security group..') as act:
        while True:
            try:
                sg.delete()
            except:
                time.sleep(3)
                act.progress()
            if not ctx.obj.get_security_group(sg.name):
                # seems to be deleted
                break

    with Action('Deleting keypair..'):
        keypair = conn.get_key_pair(sg.name)
        keypair.delete()

    with Action('Deleting IAM role..'):
        iam_conn = boto.iam.connect_to_region(region)
        iam_conn.remove_role_from_instance_profile(instance_profile_name=sg.name, role_name=sg.name)
        iam_conn.delete_instance_profile(sg.name)
        iam_conn.delete_role(sg.name)

    with Action('Deleting LB security group..'):
        lb_sg_name = 'app-{}-lb'.format(application_name)
        lb_sg = ctx.obj.get_security_group(lb_sg_name)
        if lb_sg:
            lb_sg.delete()


@versions.command('logs')
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('start', default='-1h')
@click.argument('until', default='now')
@click.argument('size', default=LOGGLY_REQUEST_SIZE)
@click.pass_context
def show_version_logs(ctx, application_name: str, application_version, start, until, size):
    """
    Show logs of one application version via Loggly
    """
    app_config = ctx.obj.config
    app_identifier = '{}-{}'.format(application_name, application_version)
    account = app_config['loggly_account']

    response_in_json = request_loggly_logs(ctx, account, app_identifier, start, until, size)

    # output log data
    for event in response_in_json['events']:
        print_if_app_log(event)


@instances.command('logs')
@click.argument('instance-id')
@click.argument('remote-file-path')
@click.pass_context
def cat_remote_file(ctx, instance_id: str, remote_file_path: str):
    """
    Print contents of one remote file on a give instance
    """
    instance = ctx.obj.get_instance_by_id(instance_id)
    if instance is None:
        error('Could not find instance with id "{}"'.format(instance_id))
        return

    app_name = instance.key_name.replace('app-', '', 1)
    app = ctx.obj.get_application(app_name)

    print_remote_file(instance, app, remote_file_path)


@cli.command()
@click.option('--url', '-u', help='SAML identity provider URL', metavar='URL')
@click.option('--user', '-U', help='SAML Username', metavar='USERNAME')
@click.option('--password', '-p', help='SAML Password', metavar='PWD')
@click.option('--role', '-r', help='Role to select (if user has multiple SAML roles)')
@click.option('--print-env-vars', help='Print AWS credentials as environment variables', is_flag=True)
@click.option('--overwrite-default-credentials', '-o', help='Overwrite [default] AWS credentials too', is_flag=True)
@click.pass_context
def login(ctx, url, user, password, role, print_env_vars, overwrite_default_credentials):
    """
    Login to SAML Identity Provider (shibboleth-idp) and retrieve temporary AWS credentials
    """
    url = url or ctx.obj.saml_identity_provider_url

    if not url:
        raise click.UsageError('Please specify SAML identity provider URL in config file or use "--url"')

    user = user or ctx.obj.saml_user or click.prompt('SAML Username')
    role = role or ctx.obj.saml_role

    saml_login(ctx.obj.profile, ctx.obj.region, url, user, password, role, print_env_vars,
               overwrite_default_credentials)


@versions.command('tail')
@click.argument('application-name', callback=validate_application_name)
@click.argument('application-version', callback=validate_application_version)
@click.argument('start', default=LOGGLY_TAIL_START_TIME)
@click.argument('log-request-size', default=LOGGLY_REQUEST_SIZE)
@click.pass_context
def tail_version_logs(ctx, application_name: str, application_version, start, log_request_size):
    """
    Tail logs of one application version via Loggly
    """
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

            print_if_app_log(event)

        time.sleep(1)


def is_credentials_expired_error(e: BotoServerError) -> bool:
    return (e.status == 400 and 'request has expired' in e.message.lower()) or \
           (e.status == 403 and 'security token included in the request is expired' in e.message.lower())


def main():
    try:
        cli()
    except BotoServerError as e:
        if is_credentials_expired_error(e):
            sys.stderr.write('AWS credentials have expired. Use "minion login" to get a new temporary access key.\n')
            sys.exit(1)
        else:
            raise


if __name__ == '__main__':
    main()
