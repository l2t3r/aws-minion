import configparser
import datetime
import os
import time

AWS_CREDENTIALS_PATH = '~/.aws/credentials'


def parse_time(s: str) -> float:
    try:
        utc = datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
        return utc - time.timezone
    except:
        return None


def format_time(dt: datetime.datetime=None) -> str:
    """
    >>> dt = datetime.datetime.utcnow(); (dt.timestamp() - time.timezone) - parse_time(format_time(dt))
    0.0
    """
    if not dt:
        dt = datetime.datetime.utcnow()
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def write_aws_credentials(profile, key_id, secret, session_token=None):
    credentials_path = os.path.expanduser(AWS_CREDENTIALS_PATH)
    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
    config = configparser.ConfigParser()
    if os.path.exists(credentials_path):
        config.read(credentials_path)

    config[profile] = {}
    config[profile]['aws_access_key_id'] = key_id
    config[profile]['aws_secret_access_key'] = secret
    if session_token:
        # apparently the different AWS SDKs either use "session_token" or "security_token", so set both
        config[profile]['aws_session_token'] = session_token
        config[profile]['aws_security_token'] = session_token

    with open(credentials_path, 'w') as fd:
        config.write(fd)
