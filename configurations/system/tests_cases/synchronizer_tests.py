import inspect

from .structures import TestConfiguration
from systest_utils import statics


class SynchronizerTests(object):

    @staticmethod
    def synchronizer():
        from tests_scripts.helm.synchronizer import Synchronizer

        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            workloads=statics.DEFAULT_SYNCHRONIZER_PATH,
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
            reconciliation_interval_minutes=10
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

    @staticmethod
    def synchronizer_race_condition():
        from tests_scripts.helm.synchronizer import SynchronizerRaceCondition
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            workload=join(statics.DEFAULT_SYNCHRONIZER_PATH, "deployment.yaml"),
            test_obj=SynchronizerRaceCondition,
        )

    @staticmethod
    def synchronizer_kubescape_crds():
        from tests_scripts.helm.synchronizer import SynchronizerKubescapeCRDs
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            crds=statics.DEFAULT_SYNCHRONIZER_CRDS_PATH,
            test_obj=SynchronizerKubescapeCRDs,
        )