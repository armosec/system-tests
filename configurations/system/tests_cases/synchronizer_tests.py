import inspect

from systest_utils import statics
from .structures import TestConfiguration


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


