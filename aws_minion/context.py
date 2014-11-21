
import boto.ec2

IDENTIFIER_PREFIX = 'app-'

class Application:

    def __init__(self, name):
        self.name = name

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
        app = Application(application_name)
        return app
