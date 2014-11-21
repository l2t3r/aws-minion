
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
