k8s_kinds = ["ComponentStatus", "ConfigMap", "ControllerRevision", "CronJob",
             "CustomResourceDefinition", "DaemonSet", "Deployment", "Endpoints", "Event", "HorizontalPodAutoscaler",
             "Ingress", "Job", "Lease", "LimitRange", "LocalSubjectAccessReview", "MutatingWebhookConfiguration",
             "Namespace", "NetworkPolicy", "Node", "PersistentVolume", "PersistentVolumeClaim", "Pod",
             "PodDisruptionBudget", "PodSecurityPolicy", "PodTemplate", "PriorityClass", "ReplicaSet",
             "ReplicationController", "ResourceQuota", "Role", "RoleBinding", "Secret", "SelfSubjectAccessReview",
             "SelfSubjectRulesReview", "Service", "ServiceAccount", "StatefulSet", "StorageClass",
             "SubjectAccessReview", "TokenReview", "ValidatingWebhookConfiguration", "VolumeAttachment"]

k8s_kinds_lower = [i.lower() for i in k8s_kinds]


class Wlid(object):
    '''
        Workload ID representation object
            Parses:
                wlid string: Wlid('wlid://cluster-MyCluster/namespace-MyNamespace/pod-MyPod')
                yaml: Wlid(yaml=<YAML>, cluster='MyCluster')
                arguments: Wlid(cluster='MyCluster',namespace='MyNamespace',workload_kind='pod',workload='MyPod')
    '''

    def __init__(self, wlid: str = None, **kwargs):
        self.level0 = ''
        self.level1 = ''
        self.kind = ''
        self.name = ''

        if wlid:
            try:
                wlid_str = wlid[len('wlid://'):]
                wlid_slices = wlid_str.split('/')
                self.level0 = wlid_slices[0].split('-', maxsplit=1)[1]
                self.level1 = wlid_slices[1].split('-', maxsplit=1)[1]
                kind_and_name = wlid_slices[2].split('-', maxsplit=1)
                self.kind = kind_and_name[0].lower()
                self.name = kind_and_name[1]
            except:
                raise Exception(f"wlid {wlid} is not valid")
        if 'yaml' in kwargs:
            yaml = kwargs['yaml']
            self.kind = yaml['kind']
            self.name = yaml['metadata']['name']
            if 'namespace' in yaml['metadata']:
                self.level1 = yaml['metadata']['namespace']

        if 'cluster' in kwargs:
            self.level0 = kwargs['cluster']
        if 'namespace' in kwargs:
            self.level1 = kwargs['namespace']
        if 'datacenter' in kwargs:
            self.level0 = kwargs['datacenter']
        if 'project' in kwargs:
            self.level1 = kwargs['project']
        if 'kind' in kwargs:
            self.kind = kwargs['kind']
        if 'name' in kwargs:
            self.name = kwargs['name']

        self.kind = self.kind.lower()
        self.is_k8s = self.is_k8s(self.kind)

    def __str__(self):
        level0 = "cluster" if self.is_k8s else "datacenter"
        level1 = "namespace" if self.is_k8s else "project"

        return f'wlid://{level0}-{self.level0}/{level1}-{self.level1}/{self.kind}-{self.name}'

    def get_wlid(self):
        return self.__str__()

    @staticmethod
    def is_k8s(kind):
        return kind in k8s_kinds_lower

    @staticmethod
    def get_name(wlid):
        w = Wlid(wlid)
        return w.name

    @staticmethod
    def get_kind(wlid):
        w = Wlid(wlid)
        return w.kind

    @staticmethod
    def get_datacenter(wlid):
        w = Wlid(wlid)
        return w.level0

    @staticmethod
    def get_cluster(wlid):
        w = Wlid(wlid)
        return w.level0

    @staticmethod
    def get_project(wlid):
        w = Wlid(wlid)
        return w.level1

    @staticmethod
    def get_namespace(wlid):
        w = Wlid(wlid)
        return w.level1

    # @staticmethod
    # def get_k8s_kind(kind):
    #     for i in k8s_kinds:
    #         if i.lower() == kind:
    #             return i
    #     return kind

    @staticmethod
    def get_slices(wlid):
        w = Wlid(wlid)
        return w.level0, w.level1, w.kind, w.name

    @staticmethod
    def is_valid(wlid):
        wlid = wlid[len('wlid://'):]
        wlid_parts = wlid.split('/')
        if len(wlid_parts) != 3:
            raise Exception('Not a valid workload ID string')
        if not wlid_parts[2].count('-'):
            raise Exception('Not a valid workload ID string')
