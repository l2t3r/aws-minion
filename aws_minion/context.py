
import boto.ec2
import yaml

IDENTIFIER_PREFIX = 'app-'


class Application:

    def __init__(self, name: str, conn):
        self.name = name
        self.security_group = None

        all_security_groups = conn.get_all_security_groups()
        sg_name = self.identifier
        for _sg in all_security_groups:
            if _sg.name == sg_name:
                self.security_group = _sg
                self.manifest = yaml.safe_load(_sg.tags['Manifest'])

        if not self.security_group:
            raise Exception('Application not found')

    @property
    def identifier(self):
        return IDENTIFIER_PREFIX + self.name


class Context:
    def __init__(self, config):
        self.config = config

    @property
    def region(self):
        return self.config['region']

    @property
    def vpc(self):
        return self.config['vpc']

    @property
    def domain(self):
        return self.config['domain']

    def get_application(self, application_name: str) -> Application:

        conn = boto.ec2.connect_to_region(self.region)
        app = Application(application_name, conn)
        return app
