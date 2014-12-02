import os
from textwrap import dedent

AWS_CREDENTIALS_PATH = '~/.aws/credentials'


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
