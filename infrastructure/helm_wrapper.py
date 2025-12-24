import os
import shutil

from systest_utils import TestUtil, statics, Logger
import yaml

CREATE_CERTIFICATE_SCRIPT_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "create_certificate.sh")
CREATE_CONFIGMAPS_SCRIPT_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "create_configmaps.sh")
BASE64_ENCODED_SECRET_SCRIPT_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "base64_encoded_secret.sh")
SAN_SCR_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "san_scr.cnf")
HTTPD_CONF_PATH = os.path.join(statics.DEFAULT_HELM_PROXY_PATH, "httpd.conf")


class HelmWrapper(object):
    def __init__(self):
        pass

    @staticmethod
    def add_armo_to_repo():
        TestUtil.run_command(
            command_args=["helm", "repo", "add", "kubescape", "https://kubescape.github.io/helm-charts/"])

    @staticmethod
    def add_armosec_to_repo():
        TestUtil.run_command(
            command_args=["helm", "repo", "add", "armosec", "https://armosec.github.io/helm-charts/"])

    @staticmethod
    def upgrade_armo_in_repo():
        TestUtil.run_command(command_args=["helm", "repo", "update", "kubescape"])
        # os.system("helm repo update armo")

    @staticmethod
    def upgrade_armosec_in_repo():
        TestUtil.run_command(command_args=["helm", "repo", "update", "armosec"])

    @staticmethod
    def is_multi_prod_environment(server: str) -> bool:
        """
        Check if the environment is a multi-prod environment based on server URL.
        Multi-prod environments have URLs like: api.stage-us-east-1.r7.armo-cadr.com or api.prod-*.r7.armo-cadr.com
        """
        if not server:
            return False
        return "r7.armo-cadr.com" in server or server.startswith("api.stage-") or server.startswith("api.prod-")

    @staticmethod
    def get_current_kubectl_context() -> str:
        """
        Get the current kubectl context name.
        """
        return_code, return_obj = TestUtil.run_command(
            command_args=["kubectl", "config", "current-context"],
            display_stdout=False
        )
        if return_code != 0:
            Logger.logger.warning("Failed to get kubectl current context, using cluster_name as fallback")
            return ""
        context = return_obj.stdout.decode("utf-8").strip()
        return context

    @staticmethod
    def install_armo_helm_chart(customer: str, access_key: str, server: str, cluster_name: str,
                                repo: str = statics.HELM_REPO, namespace: str = statics.CA_NAMESPACE_FROM_HELM_NAME,
                                create_namespace: bool = True,
                                helm_kwargs: dict = {}, use_offline_db: bool = True, temp_dir: str = None, helm_branch: str = None):
        # Check if this is a multi-prod environment
        is_multi_prod = HelmWrapper.is_multi_prod_environment(server)
        
        if is_multi_prod:
            # For multi-prod environments, clone from armosec/helm-charts repo and use rapid7-operator chart
            Logger.logger.info("Detected multi-prod environment, using armosec/helm-charts repository")
            
            # Clone armosec/helm-charts repository
            if temp_dir is None:
                temp_dir = os.path.join(os.getcwd(), "temp")
            armosec_helm_charts_dir = os.path.join(temp_dir, "armosec-helm-charts")
            
            # Remove existing directory if it exists
            if os.path.exists(armosec_helm_charts_dir):
                shutil.rmtree(armosec_helm_charts_dir)
            
            # Clone the repository (use branch if provided, otherwise default to main)
            branch = helm_branch if helm_branch and helm_branch != "release" else "main"
            Logger.logger.info(f"Cloning armosec/helm-charts from branch: {branch}")
            clone_command = ["git", "clone", "-b", branch, "https://github.com/armosec/helm-charts.git", armosec_helm_charts_dir]
            return_code, return_obj = TestUtil.run_command(command_args=clone_command, timeout=360)
            if return_code != 0:
                # If branch doesn't exist, try main/master
                Logger.logger.warning(f"Failed to clone branch {branch}, trying main")
                if os.path.exists(armosec_helm_charts_dir):
                    shutil.rmtree(armosec_helm_charts_dir)
                clone_command = ["git", "clone", "https://github.com/armosec/helm-charts.git", armosec_helm_charts_dir]
                return_code, return_obj = TestUtil.run_command(command_args=clone_command, timeout=360)
                if return_code != 0:
                    raise Exception(f"Failed to clone armosec/helm-charts repository: {return_obj.stderr}")
            
            # Use local path to rapid7-operator chart
            rapid7_chart_path = os.path.join(armosec_helm_charts_dir, "charts", "rapid7-operator")
            if not os.path.exists(rapid7_chart_path):
                raise Exception(f"Chart path not found: {rapid7_chart_path}")
            
            # Update helm dependencies
            HelmWrapper.helm_dependency_update(rapid7_chart_path)
            
            # Get current kubectl context for cluster name
            current_context = HelmWrapper.get_current_kubectl_context()
            if not current_context:
                current_context = cluster_name
                Logger.logger.warning(f"Could not get kubectl current-context, using cluster_name: {cluster_name}")
            else:
                Logger.logger.info(f"Using kubectl current-context as cluster name: {current_context}")
            
            # Get imagePullSecret.password from environment variable
            image_pull_secret_password = os.environ.get("NA_IMAGE_PULL_SECRET_PASSWORD", "")
            if not image_pull_secret_password:
                Logger.logger.warning("NA_IMAGE_PULL_SECRET_PASSWORD environment variable not set")
            
            # Build command for multi-prod using local chart path
            command_args = ["helm", "upgrade", "--debug", "--install", "rapid7", rapid7_chart_path, "-n", namespace,
                            "--set", "kubescape-operator.clusterName={}".format(current_context),
                            "--set", "kubescape-operator.account={}".format(customer),
                            "--set", "kubescape-operator.server={}".format(server)]
            
            if access_key != "":
                command_args.extend(["--set", "kubescape-operator.accessKey={}".format(access_key)])
            
            if image_pull_secret_password:
                command_args.extend(["--set", "kubescape-operator.imagePullSecret.password={}".format(image_pull_secret_password)])
        else:
            # Standard installation for non-multi-prod environments
            command_args = ["helm", "upgrade", "--debug", "--install", "kubescape", repo, "-n", namespace,
                            "--set", "account={x}".format(x=customer),
                            "--set", "server={x}".format(x=server),
                            "--set", "clusterName={}".format(cluster_name), "--set", "logger.level=debug"]
        if create_namespace:
            command_args.append("--create-namespace")

        if not is_multi_prod:
            # Standard parameters for non-multi-prod environments
            if access_key != "":
                command_args.extend(["--set", "accessKey={x}".format(x=access_key)])

            # by default use offline vuln DB
            if use_offline_db:
                command_args.extend(["--set", f"{statics.HELM_OFFLINE_VULN_DB}=True"])

            # disable security framework scan
            # command_args.extend(["--set", "operator.triggerSecurityFramework=false"])
            if os.environ.get("DISABLE_RELEVANCY") == "true":
                command_args.extend(["--set", "capabilities.relevancy=disable"])
            if os.environ.get("DISABLE_NODE_AGENT") == "true": 
                command_args.extend(["--set", "capabilities.runtimeObservability=disable", 
                                     "--set", "capabilities.relevancy=disable", 
                                     "--set", "capabilities.networkPolicyService=disable"])

            # reduce resources requests
            command_args.extend(["--set", "kubescape.resources.requests.cpu=100m"])
            command_args.extend(["--set", "kubescape.resources.requests.memory=200Mi"])
            command_args.extend(["--set", "nodeAgent.resources.requests.cpu=50m"])
            command_args.extend(["--set", "nodeAgent.resources.requests.memory=100Mi"])
            command_args.extend(["--set", "kubevuln.resources.requests.cpu=100m"])
            command_args.extend(["--set", "kubevuln.resources.requests.memory=500Mi"])
            command_args.extend(["--set", "storage.resources.requests.cpu=50m"])
            command_args.extend(["--set", "storage.resources.requests.memory=200Mi"])
            command_args.extend(["--set", "synchronizer.resources.requests.cpu=50m"])
            command_args.extend(["--set", "synchronizer.resources.requests.memory=150Mi"])

        # Add any additional helm_kwargs (works for both multi-prod and standard)
        for k, v in helm_kwargs.items():
            command_args.extend(["--set", f"{k}={v}"])

        return_code, return_obj = TestUtil.run_command(command_args=command_args, timeout=360)
        assert return_code == 0, "return_code is {}\nreturn_obj\n stdout: {}\n stderror: {}".format(return_code,
                                                                                                    return_obj.stdout,
                                                                                                    return_obj.stderr)

    @staticmethod
    def uninstall_kubescape_chart(release_name: str = None):
        """
        Uninstall the Helm chart.
        For multi-prod environments, use release_name='rapid7', otherwise use default 'kubescape'.
        """
        if release_name is None:
            release_name = statics.CA_HELM_NAME
        TestUtil.run_command(
            command_args=["helm", "-n", statics.CA_NAMESPACE_FROM_HELM_NAME, "uninstall", release_name])

    @staticmethod
    def remove_armo_from_repo():
        TestUtil.run_command(command_args=["helm", "repo", "remove", "kubescape"])

    ################### Helm proxy related functions

    @staticmethod
    def create_helm_proxy_certificates():
        TestUtil.run_command(command_args=f"chmod u+x {CREATE_CERTIFICATE_SCRIPT_PATH}")
        status, return_obj = TestUtil.run_command(command_args=[CREATE_CERTIFICATE_SCRIPT_PATH])
        assert status == 0, "Failed to get certificates for helm proxy. return_code is {}\nreturn_obj\n stdout: {}\n stderror: {}".format(
            status, return_obj.stdout, return_obj.stderr)
        Logger.logger.info('Helm proxy certificates were created.')

    @staticmethod
    def create_helm_proxy_configmaps():
        TestUtil.run_command(command_args=f"chmod u+x {CREATE_CONFIGMAPS_SCRIPT_PATH}")
        status, return_obj = TestUtil.run_command(command_args=[CREATE_CONFIGMAPS_SCRIPT_PATH])
        assert status == 0, "Failed to create configmaps for helm proxy. return_code is {}\nreturn_obj\n stdout: {}\n stderror: {}".format(
            status, return_obj.stdout, return_obj.stderr)
        Logger.logger.info('Helm proxy configmaps were created.')

    @staticmethod
    def set_cnf_property(file_path, property_name, new_value):
        with open(file_path, 'r') as file:
            lines = file.readlines()

        for i, line in enumerate(lines):
            if line.startswith(property_name):
                # Modify the line with the new value
                lines[i] = f"{property_name} {new_value}\n"
                break

        with open(file_path, 'w') as file:
            file.writelines(lines)

    @staticmethod
    def update_helm_proxy_network_policy_namespace(filepath, namespace):

        # Read the YAML file
        with open(filepath, 'r') as file:
            yaml_data = yaml.safe_load(file)

        # Update the ingress and egress match labels
        yaml_data['spec']['ingress'][0]['from'][0]['namespaceSelector']['matchLabels']['name'] = namespace
        yaml_data['spec']['egress'][0]['to'][0]['namespaceSelector']['matchLabels']['name'] = namespace

        # Save the updated YAML to a file
        with open(filepath, 'w') as file:
            yaml.dump(yaml_data, file)

    @staticmethod
    def configure_helm_proxy(helm_proxy_url, namespace):
        Logger.logger.info(f"Start configuring helm proxy with url: '{helm_proxy_url}'")
        helm_proxy_domain = helm_proxy_url.split("//")[1]
        HelmWrapper.set_cnf_property(SAN_SCR_PATH, "CN =", helm_proxy_domain)
        HelmWrapper.set_cnf_property(SAN_SCR_PATH, "DNS.1 =", helm_proxy_domain)
        HelmWrapper.set_cnf_property(SAN_SCR_PATH, "DNS.2 =", helm_proxy_domain.split(".")[0])
        HelmWrapper.set_cnf_property(HTTPD_CONF_PATH, "ServerName", helm_proxy_domain)

        HelmWrapper.create_helm_proxy_certificates()
        HelmWrapper.create_helm_proxy_configmaps()

        TestUtil.run_command(command_args=f"chmod u+x {BASE64_ENCODED_SECRET_SCRIPT_PATH}")
        status, return_obj = TestUtil.run_command(command_args=[BASE64_ENCODED_SECRET_SCRIPT_PATH],
                                                  display_stdout=False)

        Logger.logger.info(f"Helm proxy with url: '{helm_proxy_url}' configured successfully.")

        obj = {"global.httpsProxy": helm_proxy_url}

        r = return_obj.stdout.decode("utf-8")
        if r != '\n':
            obj["global.proxySecretFile"] = r
        return obj

    @staticmethod
    def helm_dependency_update(repo):
        TestUtil.run_command(command_args=["helm", "dependency", "update", repo])
