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
    

    # seccomp profile - backend list
    @staticmethod
    def seccomp_profile_workloads_list():
        from tests_scripts.helm.seccomp import SeccompProfileList
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            seccomp_overly_permissive=join(statics.DEFAULT_SECCOMP_PATH, "seccomp-alpine-overly-permissive.yaml"),
            seccomp_optimized=join(statics.DEFAULT_SECCOMP_PATH, "seccomp-alpine-optimized.yaml"),
            workload_missing=join(statics.DEFAULT_SECCOMP_PATH, "alpine-seccomp-pod-missing.yaml"),
            workload_overly_permissive=join(statics.DEFAULT_SECCOMP_PATH, "alpine-seccomp-pod-overly-permissive.yaml"),
            workload_optimized=join(statics.DEFAULT_SECCOMP_PATH, "alpine-seccomp-pod-optimized.yaml"),
            expected={
                "alpine-syscall-missing": {"profileStatuses": [statics.SECCOMP_STATUS_MISSING]},
                "alpine-syscall-overly-permissive": {"profileStatuses": [statics.SECCOMP_STATUS_OVERLY_PERMISSIVE]},
                "alpine-syscall-optimized": {"profileStatuses": [statics.SECCOMP_STATUS_OPTIMIZED, 
                                                                 statics.SECCOMP_STATUS_MISCONFIGURED,
                                                                 statics.SECCOMP_STATUS_OVERLY_PERMISSIVE]},
            },
            test_obj=SeccompProfileList)

    # seccomp profile - backend generate
    @staticmethod
    def seccomp_profile_generate():
        from tests_scripts.helm.seccomp import SeccompProfileGenerate
        from os.path import join
        return TestConfiguration(
            name=inspect.currentframe().f_code.co_name,
            seccomp_overly_permissive=join(statics.DEFAULT_SECCOMP_PATH, "seccomp-alpine-overly-permissive.yaml"),
            workload_missing=join(statics.DEFAULT_SECCOMP_PATH, "alpine-seccomp-pod-missing.yaml"),
            workload_overly_permissive=join(statics.DEFAULT_SECCOMP_PATH, "alpine-seccomp-pod-overly-permissive.yaml"),
            expected={
                "alpine-syscall-overly-permissive": {"profileStatuses": [statics.SECCOMP_STATUS_OVERLY_PERMISSIVE]},
            },
            test_obj=SeccompProfileGenerate)
