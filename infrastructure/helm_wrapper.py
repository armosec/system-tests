import os

from systest_utils import TestUtil, statics


class HelmWrapper(object):
    def __init__(self):
        pass

    @staticmethod
    def add_armo_to_repo():
        TestUtil.run_command(command_args=["helm", "repo", "add", "kubescape", "https://kubescape.github.io/helm-charts/"])

    @staticmethod
    def upgrade_armo_in_repo():
        TestUtil.run_command(command_args=["helm", "repo", "update", "kubescape"])
        # os.system("helm repo update armo")

    @staticmethod
    def install_armo_helm_chart(customer: str, environment: str, cluster_name: str,
                                repo: str=statics.HELM_REPO, helm_kwargs:dict={}):
        repo = "/home/daniel/armo/helm-charts/charts/kubescape-cloud-operator"
        command_args = ["helm", "upgrade", "--debug", "--install", "kubescape", repo, "-n", statics.CA_NAMESPACE_FROM_HELM_NAME,
                        "--create-namespace", "--set", "account={x}".format(x=customer),
                        "--set", "clusterName={}".format(cluster_name), "--set", "logger.level=debug"]

        # by default use offline vuln DB
        command_args.extend(["--set", f"{statics.HELM_OFFLINE_VULN_DB}=True"])

        #node agent resources
        # command_args.extend(["--set", f"{statics.HELM_NODE_AGENT_REQ_CPU}=1000m"])
        command_args.extend(["--set", f"{statics.HELM_NODE_AGENT_LIMITS_CPU}=1000m"])
        # command_args.extend(["--set", f"{statics.HELM_NODE_AGENT_REQ_MEMORY}=1000Mi"])
        command_args.extend(["--set", f"{statics.HELM_NODE_AGENT_LIMITS_MEMORY}=2000Mi"])

        #storage resources
        # command_args.extend(["--set", f"{statics.HELM_STORAGE_REQ_CPU}=1000m"])
        command_args.extend(["--set", f"{statics.HELM_STORAGE_LIMITS_CPU}=1000m"])
        # command_args.extend(["--set", f"{statics.HELM_STORAGE_REQ_MEMORY}=1000Mi"])
        command_args.extend(["--set", f"{statics.HELM_STORAGE_LIMITS_MEMORY}=2000Mi"])
        
        for k, v in helm_kwargs.items():
            command_args.extend(["--set", f"{k}={v}"])


        if environment in ["development", "dev", "development-egg", "dev-egg"]:
            command_args.extend(["--set", "environment=dev"])
        elif environment in ["staging", "stage", "staging-egg", "stage-egg"]:
            command_args.extend(["--set", "environment=staging"])
        return_code, return_obj = TestUtil.run_command(command_args=command_args, timeout=360)
        assert return_code == 0, "return_code is {}\nreturn_obj\n stdout: {}\n stderror: {}".format(return_code, return_obj.stdout, return_obj.stderr)

    @staticmethod
    def uninstall_armo_helm_chart():
        TestUtil.run_command(command_args=["helm", "-n", statics.CA_NAMESPACE_FROM_HELM_NAME, "uninstall", statics.CA_HELM_NAME])

    @staticmethod
    def remove_armo_from_repo():
        TestUtil.run_command(command_args=["helm", "repo", "remove", "kubescape"])
