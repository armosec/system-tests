class SID(object):
    '''
        Workload ID representation object
            Parses:
                wlid string: Wlid('wlid://cluster-MyCluster/namespace-MyNamespace/pod-MyPod')
                yaml: Wlid(yaml=<YAML>, cluster='MyCluster')
                arguments: Wlid(cluster='MyCluster',namespace='MyNamespace',workload_kind='pod',workload='MyPod')
    '''

    def __init__(self, sid: str = None, **kwargs):
        self.cluster = ''
        self.namespace = ''
        self.kind = 'secret'
        self.name = ''
        self.subsecret = ''

        if sid:
            try:
                sid_str = sid[len('sid://'):]
                sid_slices = sid_str.split('/')
                self.cluster = sid_slices[0].split('-', maxsplit=1)[1]
                self.namespace = sid_slices[1].split('-', maxsplit=1)[1]
                kind_and_name = sid_slices[2].split('-', maxsplit=1)
                self.name = kind_and_name[1]
                if len(sid_slices) == 4:
                    self.subsecret = sid_slices[3].split('-', maxsplit=1)[1]
            except:
                raise Exception(f"sid {sid} is not valid")

        if 'cluster' in kwargs:
            self.cluster = kwargs['cluster']
        if 'namespace' in kwargs:
            self.namespace = kwargs['namespace']
        if 'name' in kwargs:
            self.name = kwargs['name']
        if 'subsecret' in kwargs:
            self.subsecret = kwargs['subsecret']

    def __str__(self):
        subsecret = ""
        if self.subsecret != "":
            subsecret = f"/subsecret-{self.subsecret}"
        return f'sid://cluster-{self.cluster}/namespace-{self.namespace}/secret-{self.name}{subsecret}'

    def get_sid(self):
        return self.__str__()

    @staticmethod
    def get_name(sid):
        s = SID(sid)
        return s.name

    @staticmethod
    def get_cluster(sid):
        s = SID(sid)
        return s.cluster

    @staticmethod
    def get_namespace(sid):
        s = SID(sid)
        return s.namespace

    @staticmethod
    def get_subsecret(sid):
        s = SID(sid)
        return s.subsecret

    @staticmethod
    def add_subsecret(sid: str, subsecret: str):
        s = SID(sid=sid, subsecret=subsecret)
        return s.get_sid()

    @staticmethod
    def get_slices(sid):
        s = SID(sid)
        return s.cluster, s.namespace, s.kind, s.name, s.subsecret

    @staticmethod
    def is_valid(sid):
        sid = sid[len('sid://'):]
        sid_parts = sid.split('/')
        if not 3 <= len(sid_parts) <= 4:
            raise Exception('Not a valid secret ID string')
