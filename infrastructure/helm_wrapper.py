import os

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
        TestUtil.run_command(command_args=["helm", "repo", "add", "kubescape", "https://kubescape.github.io/helm-charts/"])

    @staticmethod
    def upgrade_armo_in_repo():
        TestUtil.run_command(command_args=["helm", "repo", "update", "kubescape"])
        # os.system("helm repo update armo")

    @staticmethod
    def install_armo_helm_chart(customer: str, environment: str, cluster_name: str,
                                repo: str=statics.HELM_REPO, helm_kwargs:dict={}):
        command_args = ["helm", "upgrade", "--debug", "--install", "kubescape", repo, "-n", statics.CA_NAMESPACE_FROM_HELM_NAME,
                        "--create-namespace", "--set", "account={x}".format(x=customer),
                        "--set", "clusterName={}".format(cluster_name), "--set", "logger.level=debug"]

        # by default use offline vuln DB
        command_args.extend(["--set", f"{statics.HELM_OFFLINE_VULN_DB}=True"])

        # disable security framework scan
        # command_args.extend(["--set", "operator.triggerSecurityFramework=false"])

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



    ################### Helm proxy related functions

    @staticmethod
    def create_helm_proxy_certificates():
        TestUtil.run_command(command_args=f"chmod u+x {CREATE_CERTIFICATE_SCRIPT_PATH}")
        status, return_obj = TestUtil.run_command(command_args=[CREATE_CERTIFICATE_SCRIPT_PATH])
        assert status == 0, "Failed to get certificates for helm proxy. return_code is {}\nreturn_obj\n stdout: {}\n stderror: {}".format(status, return_obj.stdout, return_obj.stderr)
        Logger.logger.info('Helm proxy certificates were created.')


    @staticmethod
    def create_helm_proxy_configmaps():
        TestUtil.run_command(command_args=f"chmod u+x {CREATE_CONFIGMAPS_SCRIPT_PATH}")
        status, return_obj = TestUtil.run_command(command_args=[CREATE_CONFIGMAPS_SCRIPT_PATH])
        assert status == 0, "Failed to create configmaps for helm proxy. return_code is {}\nreturn_obj\n stdout: {}\n stderror: {}".format(status, return_obj.stdout, return_obj.stderr)
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
        status, return_obj =  TestUtil.run_command(command_args=[BASE64_ENCODED_SECRET_SCRIPT_PATH], display_stdout=False)

        Logger.logger.info(f"Helm proxy with url: '{helm_proxy_url}' configured successfully.")

        return {"global.httpsProxy": helm_proxy_url, 
                "global.proxySecretFile": return_obj.stdout.decode("utf-8")}
        
