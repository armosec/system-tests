import inspect

from .structures import TestConfiguration
from systest_utils import statics


class SynchronizerTests(object):

    @staticmethod
    def synchronizer():
        from tests_scripts.helm.synchronizer import Synchronizer
        from os.path import join

        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            deployment=join(statics.DEFAULT_SYNCHRONIZER_PATH, "deployment.yaml"),
            replicaset=join(statics.DEFAULT_SYNCHRONIZER_PATH, "replicaset.yaml"),
            statefulset=join(statics.DEFAULT_SYNCHRONIZER_PATH, "statefulset.yaml"),
            daemonset=join(statics.DEFAULT_SYNCHRONIZER_PATH, "daemonset.yaml"),
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

