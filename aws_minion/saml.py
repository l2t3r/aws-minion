import codecs
from textwrap import dedent
from xml.etree import ElementTree
from aws_minion.aws import write_aws_credentials
import botocore.session
from bs4 import BeautifulSoup
import click
import keyring
import requests
from aws_minion.console import Action, choice


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
    'AWS Account 123: Shibboleth-PowerUser'
    """
    provider_arn, role_arn = role
    return 'AWS Account {}: {}'.format(role_arn.split(':')[4], role_arn.split('/')[-1])


def get_roles(saml_xml: str) -> list:
    """

    >>> get_roles('<xml xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Assertion></Assertion></xml>')
    []
    """
    tree = ElementTree.fromstring(saml_xml)

    assertion = tree.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')

    roles = []
    for attribute in assertion.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute[@Name]'):
        if attribute.attrib['Name'] == 'https://aws.amazon.com/SAML/Attributes/Role':
            for val in attribute.findall('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                provider_arn, role_arn = val.text.split(',')
                roles.append((provider_arn, role_arn))
    return roles


def saml_login(region, url, user, password=None, role=None, overwrite_credentials=False, print_env_vars=False):
    session = requests.Session()
    response = session.get(url)

    keyring_key = 'aws-minion.saml'
    password = password or keyring.get_password(keyring_key, user)
    if not password:
        password = click.prompt('Password', hide_input=True)

    with Action('Authenticating against {url}..', **vars()) as act:
        # NOTE: parameters are hardcoded for Shibboleth IDP
        data = {'j_username': user, 'j_password': password, 'submit': 'Login'}
        response2 = session.post(response.url, data=data)
        saml_xml = get_saml_response(response2.text)
        if not saml_xml:
            act.error('LOGIN FAILED')
            return

    keyring.set_password(keyring_key, user, password)

    with Action('Checking SAML roles..') as act:
        roles = get_roles(saml_xml)
        if not roles:
            act.error('NO VALID ROLE FOUND')
            return

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

    with Action('Assuming role "{role_label}"..', role_label=get_role_label((provider_arn, role_arn))):
        saml_assertion = codecs.encode(saml_xml.encode('utf-8'), 'base64').decode('ascii').replace('\n', '')

        session = botocore.session.get_session()
        sts = session.get_service('sts')
        operation = sts.get_operation('AssumeRoleWithSAML')

        endpoint = sts.get_endpoint(region)
        endpoint._signature_version = None
        http_response, response_data = operation.call(endpoint, role_arn=role_arn, principal_arn=provider_arn,
                                                      SAMLAssertion=saml_assertion)

        key_id = response_data['Credentials']['AccessKeyId']
        secret = response_data['Credentials']['SecretAccessKey']
        session_token = response_data['Credentials']['SessionToken']

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
        with Action('Writing temporary AWS credentials..'):
            write_aws_credentials(key_id, secret, session_token)
