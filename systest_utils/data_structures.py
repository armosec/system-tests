import copy
import json

import yaml

from . import TestUtil, statics


class DataStructures(object):
    k8s_wt = {
        "name": "",
        "cluster": "",
        "namespace": "",
        "kind": "Deployment",
        "attributes": {},
        "autoAccessTokenUpdate": True,
        "containers": []
    }

    container_templates = {
        "name": 'mysql',
        "os": 'debian',
        "imageHash": '',
        "imageTag": '',
        "architecture": '64',
    }


class DataStructuresUtils(object):
    @staticmethod
    def convert_yaml_to_wt(filename: str, **kwargs):
        if "path" in kwargs:
            filename = TestUtil.get_abs_path(relative_path=kwargs["path"], file_name=filename)
        with open(filename) as f:
            k8sobj = yaml.load(f, Loader=yaml.FullLoader)
        wt = copy.deepcopy(DataStructures.k8s_wt)
        wt['name'] = k8sobj['metadata']['name']
        wt['kind'] = k8sobj['kind']
        wt['namespace'] = kwargs['namespace'] if 'namespace' in kwargs else k8sobj['metadata'].get('namespace',
                                                                                                   'unknown')
        wt['cluster'] = kwargs.get('cluster', 'unknown')
        wt['containers'] = []
        if k8sobj['kind'] == 'Deployment':
            for k8container in k8sobj['spec']['template']['spec']['containers']:
                container = copy.deepcopy(DataStructures.container_templates)
                container['name'] = k8container['name']
                container['imageTag'] = k8container['image']
                wt['containers'].append(container)
        else:
            raise Exception('Unsupported (yet) k8s kind in convert_yaml_to_wt')
        return wt

    @staticmethod
    def create_workload_template_from_k8s_workload(yaml_file: str, namespace: str, cluster_name: str, store: str):
        wt = DataStructuresUtils.convert_yaml_to_wt(yaml_file, path=statics.DEFAULT_DEPLOYMENT_PATH,
                                                    namespace=namespace, cluster=cluster_name)
        with open(store, "w") as f:
            f.write(json.dumps(wt, indent=4))
