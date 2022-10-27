class Backend(object):

    def __init__(self, name: str, dashboard: str, tls_verify: bool = True):
        self.name = name
        self.dashboard = dashboard
        self.tls_verify = tls_verify

    def get_dashboard_url(self):
        return self.dashboard

    def get_name(self):
        return self.name

    def use_tls(self):
        return self.tls_verify


def set_backends():
    backends = list()

    # development
    backends.append(Backend(name='development',
                            dashboard='https://dashbe.eudev3.cyberarmorsoft.com',
                            tls_verify=False))

    # staging
    backends.append(Backend(name='staging',
                            dashboard='https://dashbe.eustage2.cyberarmorsoft.com'))

    # production
    backends.append(Backend(name='production',
                            dashboard='https://dashbe.euprod1.cyberarmorsoft.com',
                            tls_verify=False))

    # production2 us-east-1
    backends.append(Backend(name='production-us',
                            dashboard='https://dashbe.prod2.us.armo.cloud',
                            tls_verify=False))

    # dev2
    backends.append(Backend(name='dev2',
                            dashboard='https://dashbe.eudev2.cyberarmorsoft.com',
                            tls_verify=False))

    return {backend.get_name(): backend for backend in backends}


BACKENDS = set_backends()
