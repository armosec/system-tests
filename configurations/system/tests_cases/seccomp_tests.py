import inspect

from systest_utils import statics
from .structures import TestConfiguration


class SeccompProfileTests(object):

    # Pod level seccomp profile
    @staticmethod
    def seccomp_profile_pod():
        from tests_scripts.helm.seccomp import SeccompProfile
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            seccomp=join(statics.DEFAULT_SECCOMP_PATH, "seccomp-nginx.yaml"),
            workload=join(statics.DEFAULT_SECCOMP_PATH, "nginx-seccomp-pod.yaml"),
            want_path="default/replicaset-nginx-77b4fdf86c-nginx.json",
            test_obj=SeccompProfile)

    # Container level seccomp profile
    @staticmethod
    def seccomp_profile_container():
        from tests_scripts.helm.seccomp import SeccompProfile
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            seccomp=join(statics.DEFAULT_SECCOMP_PATH, "seccomp-nginx.yaml"),
            workload=join(statics.DEFAULT_SECCOMP_PATH, "nginx-seccomp-container.yaml"),
            want_path="default/replicaset-nginx-77b4fdf86c-nginx.json",
            test_obj=SeccompProfile)
