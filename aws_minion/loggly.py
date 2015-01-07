from textwrap import dedent
import click
import requests
from aws_minion.console import error

LOGGLY_SEARCH_REQUEST_TEMPLATE = 'https://{account}.loggly.com/apiv2/search' \
                                 '?q=syslog.appName:{app_identifier}&from={start}&until={until}&size={size}&order=asc'
LOGGLY_EVENTS_REQUEST_TEMPLATE = 'https://{account}.loggly.com/apiv2/events?rsid={rsid}'
LOGGLY_TAIL_START_TIME = '-5m'
LOGGLY_REQUEST_SIZE = 10000


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


def print_if_app_log(event):
    event_data = event['event']
    if 'json' in event_data:
        event_data = event_data['json']
        if 'log' in event_data:
            click.echo(event_data['log'], nl=False)


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
            echo '$InputFilePollInterval 1'
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
