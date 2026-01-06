import inspect

from .structures import TestConfiguration
from systest_utils import statics


class SynchronizerTests(object):

    @staticmethod
    def synchronizer():
        from tests_scripts.helm.synchronizer import Synchronizer

        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployment=join(statics.DEFAULT_SYNCHRONIZER_PATH, "deployment.yaml"),
            replicaset=join(statics.DEFAULT_SYNCHRONIZER_PATH, "replicaset.yaml"),
            statefulset=join(statics.DEFAULT_SYNCHRONIZER_PATH, "statefulset.yaml"),
            daemonset=join(statics.DEFAULT_SYNCHRONIZER_PATH, "daemonset.yaml"),
            crds=statics.DEFAULT_SYNCHRONIZER_CRDS_PATH,
            test_obj=Synchronizer)

    @staticmethod
    def synchronizer_reconciliation():
        from tests_scripts.helm.synchronizer import SynchronizerReconciliation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            workload_1=join(statics.DEFAULT_SYNCHRONIZER_PATH, "deployment.yaml"),
            workload_2=join(statics.DEFAULT_SYNCHRONIZER_PATH, "replicaset.yaml"),
            test_obj=SynchronizerReconciliation,
            reconciliation_interval_minutes=15
            )

    @staticmethod
    def synchronizer_proxy():
        from tests_scripts.helm.synchronizer import SynchronizerProxy
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            workload_1=join(statics.DEFAULT_SYNCHRONIZER_PATH, "deployment.yaml"),
            workload_2=join(statics.DEFAULT_SYNCHRONIZER_PATH, "replicaset.yaml"),
            workload_3=join(statics.DEFAULT_SYNCHRONIZER_PATH, "statefulset.yaml"),
            test_obj=SynchronizerProxy,
            proxy_config={"helm_proxy_url": statics.HELM_PROXY_URL}
        )
