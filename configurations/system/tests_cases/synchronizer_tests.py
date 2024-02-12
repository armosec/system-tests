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
            test_obj=Synchronizer,
            helm_kwargs={'capabilities.relevancy': 'disable',
                         'capabilities.configurationScan': 'disable',
                         'capabilities.continuousScan': 'disable',
                         'capabilities.nodeScan': 'disable',
                         'capabilities.vulnerabilityScan': 'disable',
                         'capabilities.runtimeObservability': 'enable',
                         'synchronizer.image.tag': 'v0.0.51',
                         })

    @staticmethod
    def synchronizer_reconciliation():
        from tests_scripts.helm.synchronizer import SynchronizerReconciliation
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            workload_1=join(statics.DEFAULT_SYNCHRONIZER_PATH, "deployment.yaml"),
            workload_2=join(statics.DEFAULT_SYNCHRONIZER_PATH, "replicaset.yaml"),
            test_obj=SynchronizerReconciliation,
            reconciliation_interval_minutes=10,
            helm_kwargs={'capabilities.relevancy': 'disable',
                         'capabilities.configurationScan': 'disable',
                         'capabilities.continuousScan': 'disable',
                         'capabilities.nodeScan': 'disable',
                         'capabilities.vulnerabilityScan': 'disable',
                         'capabilities.runtimeObservability': 'enable',
                         'synchronizer.image.tag': 'v0.0.51',
                         })


