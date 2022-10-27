import ast
import json
import os
import tempfile
from os.path import isfile
from unicodedata import name

from systest_utils.systests_utilities import TestUtil
from systest_utils.tests_logger import Logger

__POLICY_ID_STDOUT_TOKEN__ = 'Policy ID: '


class Cacli(object):
    """
    Use this class the same way you run cacli commands.
    for example:
    cacli:
        cacli wt create -i <workload-templdate.json>
        cacli sp get -n <signing-profile-name>
    This module:
        cacli.wt.create(path_to_workload_template=<workload-templdate.json>)
        cacli.sp.get(name=<signing-profile-name>)
    """

    def __init__(self, user='', password='', customer='', url=None, environment=''):
        super(Cacli, self).__init__()

        self.url = url
        self.user = user
        self.password = password
        self.customer = customer
        self.environment = environment

        self.wt = self.WorkloadTemplate()
        self.sp = self.SigningProfile()
        self.sc = self.SigningConfiguration()
        self.np = self.NetworkPolicy()
        self.inp = self.IngressNetworkPolicy()
        self.ec = self.EncryptionConfiguration()
        self.secp = self.SecretPolicy()
        self.secret = self.Secret()
        self.k8s = self.KubernetesSupport()
        self.en = self.EnforcementPolicy()

        self.login(user=self.user, password=self.password)

    @staticmethod
    def assertEqual(firts, second, msg):
        assert firts == second, msg

    @staticmethod
    def status():
        status, command_info = Cacli.run_command(command_args=['cacli', '--status'])
        return json.loads(command_info.stdout)

    @staticmethod
    def version():
        status, command_info = Cacli.run_command(command_args=['cacli', '--version'])
        return json.loads(command_info.stdout)

    def get_username(self):
        return self.user

    def get_password(self):
        return self.password

    def get_customer(self):
        return self.customer

    def login(self, user='', password=''):
        status, command_info = self.run_command(command_args=['cacli', 'login', '-u', user, '-p', password,
                                                              '-c', self.customer, '--dashboard', self.url])
        self.assertEqual(status, 0, msg="Login command failed with error {0}-{1}".format(status, command_info))

    def logout(self):
        status, command_info = self.run_command(command_args=['cacli', 'logout'])
        self.assertEqual(status, 0, msg="Logout command failed with error {0}-{1}".format(status, command_info))

    def cleanup(self, wlid: str):
        Logger.logger.info("CaCli Clean Up")
        status, command_info = self.run_command(command_args=['cacli', 'utils', 'cleanup', '-wlid', wlid])
        self.assertEqual(status, 0, msg="Clean command failed with error {0}-{1}".format(status, command_info))

    def protect(self, directory=None, wlid=str(), key_id='', gradual=False):
        status, command_info = self.run_command(
            command_args=['cacli', 'protect', 'encrypt-data', '-d', directory, '-g', "true" if gradual else "false",
                          '-kid', key_id, '-wlid', wlid])
        self.assertEqual(status, 0, msg="Protect command failed with error {0}-{1}".format(status, command_info))

    def unprotect(self):
        pass

    def register_cluster(self, cluster_name: str, output_file: str = None, run: bool = False, oci_image: bool = False,
                         password: str = None, signer_debug: bool = True):
        command_args = ['cacli', 'cluster', 'register', '-n', cluster_name]
        if output_file:
            command_args.extend(['-o', output_file])
        if run:
            command_args.append("--run")
        if password:
            command_args.extend(['-p', password])
        if oci_image:
            command_args.append("--oci-image")
        if signer_debug:
            command_args.append("--signer-debug")
        status, command_info = self.run_command(command_args=command_args)
        if status != 0:
            if "usage: cacli [-h]" in command_info.stderr:
                raise Exception("please update test cacli version: run ./create_env.sh")
            raise Exception(f"register command failed with status: {status}, error: {command_info.stderr}")

    def unregister_cluster(self, cluster_name='default'):
        status, command_info = self.run_command(
            command_args=['cacli', 'cluster', 'unregister', '-n', cluster_name], timeout=360)
        self.assertEqual(status, 0, msg="Unregister command failed with error {0}-{1}".format(status, command_info))

    @staticmethod
    def sign(wlid: str=None, container_name: str = None, cluster:str=None, namespace:str=None):
        command = ['cacli', '--debug', 'sign']
        if wlid:
            command.extend(['-wlid', wlid])
            if container_name:
                command.extend(['-c', container_name])
        elif cluster and namespace:
            command.extend(['--cluster', cluster])
            command.extend(['--namespace', namespace])
        returncode, return_obj = Cacli.run_command(command_args=command, timeout=360)
        assert returncode == 0, 'sign command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stdout)
        return return_obj

    class KubernetesSupport(object):
        @staticmethod
        def attach(wlid: str = None, cluster: str = None, namespace: str = None, inject_label: bool = False):
            command = ['cacli', 'k8s', 'attach']
            if wlid:
                command.extend(["-wlid", wlid])
            elif cluster:
                command.extend(["--cluster", cluster])
                if namespace:
                    command.extend(["--namespace", namespace])
                    if inject_label:
                        command.append("--attach-future")
            else:
                raise Exception("nothing to attach")
            status, command_info = Cacli.run_command(command_args=command)
            assert status == 0, "Attach command failed with error {0}-{1}".format(status, command_info)
            return command_info

        @staticmethod
        def attach_and_seal(wlid: str = None, attributes: dict = None):
            args = ['cacli', 'k8s', 'attach-sign']
            if wlid:
                args.extend(["-wlid", wlid])
            if attributes:
                args.append("--attributes")
                args.extend(["{}={}".format(i, j) for i, j in attributes.items()])

            status, command_info = Cacli.run_command(command_args=args)
            assert status == 0, "Attach & Seal command failed with error {0}-{1}".format(status, command_info)

        @staticmethod
        def detach(wlid: str = None, cluster: str = None, namespace: str = None):
            command = ['cacli', 'k8s', 'detach']
            if wlid:
                command.extend(["-wlid", wlid])
            elif cluster:
                command.extend(["--cluster", cluster])
                if namespace:
                    command.extend(["--namespace", namespace])
            status, command_info = Cacli.run_command(command_args=command)
            assert status == 0, "Detach command failed with error {0}-{1}".format(status, command_info)
            return command_info

        class PostureExceptions(object):
            @staticmethod
            def file_handler(pe: dict, command: str):
                temp_file = tempfile.NamedTemporaryFile(mode='w+')
                pe_json = json.dumps(pe, indent=2)
                Logger.logger.info("Posture exception policy json:\n{}".format(str(pe_json)))
                temp_file.write(pe_json)
                temp_file.flush()
                command_args = ['cacli', 'k8s', 'posture-exceptions', command, '-i', temp_file.name]
                Cacli.run_command(command_args=command_args)
                temp_file.close()

            @staticmethod
            def create(posture_exception):
                posture_exception.update_pe()
                if posture_exception.pe:
                    Cacli.KubernetesSupport.PostureExceptions.file_handler(pe=posture_exception.pe, command="create")

            @staticmethod
            def run_command(command_args: list):
                status, command_info = Cacli.run_command(command_args=command_args)
                assert status == 0, "update_posture_exception command failed with error {0}-{1}".format(status,
                                                                                                        command_info)

            @staticmethod
            def get(policy_name=''):
                command = ['cacli', 'k8s', 'posture-exceptions', 'get']
                command.extend(["-n", policy_name])
                return_code, return_obj = Cacli.run_command(command)
                assert return_code == 0, 'get posture-exceptions command failed. code: {}\nmessage: {}'.format(
                    return_code,
                    return_obj.stderr)
                try:
                    return json.loads(return_obj.stdout)
                except:
                    return return_obj.stdout

            @staticmethod
            def delete(policy_id=None, policy_name=None):
                if policy_id:
                    status, command_info = Cacli.run_command(
                        command_args=['cacli', 'k8s', 'posture-exceptions', 'delete', '-id', policy_id])
                else:
                    status, command_info = Cacli.run_command(
                        command_args=['cacli', 'k8s', 'posture-exceptions', 'delete', '-n', policy_name])

                assert status == 0, "delete_posture_exception command failed with error {0}-{1}".format(status,
                                                                                                        command_info)
        class Posture(object):
            @staticmethod
            def create(framework: str, cluster: str = None, namespace: str = None, wlid: str = None):
                command = ['cacli', 'k8s', 'posture', 'create']
                command.extend(["--framework", framework])

                if cluster:
                    command.extend(["--cluster", cluster])
                if namespace:
                    command.extend(["--namespace", namespace])
                if wlid:
                    command.extend(["--workload-id", wlid])
                returncode, return_obj = Cacli.run_command(command)
                assert returncode == 0, 'create command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                              return_obj.stderr)
                return json.loads(return_obj.stdout)

            @staticmethod
            def get(cluster: str = None, report_id: str = None):
                command = ['cacli', 'k8s', 'posture', 'get']
                if cluster:
                    command.extend(["--cluster", cluster])
                if report_id:
                    command.extend(["--report-id", report_id])
                returncode, return_obj = Cacli.run_command(command)
                assert returncode == 0, 'get command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                           return_obj.stderr)
                try:
                    return json.loads(return_obj.stdout)
                except:
                    return return_obj.stdout

        # TODO - attach-namespace

        # TODO - detach-namespace

        # TODO - restart pods

    class NetworkPolicy(object):
        @staticmethod
        def file_handler(np: dict, command: str):
            temp_file = tempfile.NamedTemporaryFile(mode='w+')
            np_json = json.dumps(np, indent=2)
            Logger.logger.info("network policy json:\n{}".format(str(np_json)))
            temp_file.write(np_json)
            temp_file.flush()
            command_args = ['cacli', 'network-policy', command, '-i', temp_file.name]
            Cacli.NetworkPolicy.run_command(command_args=command_args)
            temp_file.close()
            # os.remove(temp_file.name)

        @staticmethod
        def command_handler(policy_args, command: str):
            command_args = ['cacli', 'network-policy', command, '-n', policy_args.name]
            [command_args.extend(i) for i in [['-s-wlid', i] for i in policy_args.server_wlid]]
            [command_args.extend(i) for i in [['-c-wlid', i] for i in policy_args.client_wlid]]
            [command_args.extend(i) for i in
             [['-s-att', "{}={}".format(k, v)] for k, v in policy_args.server_attributes.items()]]
            [command_args.extend(i) for i in
             [['-c-att', "{}={}".format(k, v)] for k, v in policy_args.client_attributes.items()]]
            [command_args.extend(i) for i in [['-svc', i] for i in policy_args.k8s_service]]
            [command_args.extend(i) for i in [['-s-port', str(i)] for i in policy_args.server_port]]
            [command_args.extend(i) for i in [['-svc-port', str(i)] for i in policy_args.k8s_service_port]]

            command_args.extend(['--enforcementAction', policy_args.enforcement_action])
            command_args.extend(['--permissions', policy_args.permissions])
            command_args.extend(['--policy_type', policy_args.policy_type])
            if policy_args.permissive_mode:
                command_args.extend(['--permissive_mode'])

            Cacli.NetworkPolicy.run_command(command_args=command_args)

        @staticmethod
        def create(policy_args):
            policy_args.update_np()
            if policy_args.np:
                Cacli.NetworkPolicy.file_handler(np=policy_args.np, command="create")
            else:
                Cacli.NetworkPolicy.command_handler(policy_args=policy_args, command="create")

        @staticmethod
        def update(policy_args):
            policy_args.update_np()
            if policy_args.np:
                Cacli.NetworkPolicy.file_handler(np=policy_args.np, command="update")
            else:
                Cacli.NetworkPolicy.command_handler(policy_args=policy_args, command="update")

        @staticmethod
        def run_command(command_args: list):
            status, command_info = Cacli.run_command(command_args=command_args)
            assert status == 0, "update_network_policy command failed with error {0}-{1}".format(status, command_info)

        @staticmethod
        def delete(policy_id=None, policy_name=None):
            if policy_id:
                status, command_info = Cacli.run_command(
                    command_args=['cacli', 'network-policy', 'delete', '-id', policy_id])
            else:
                status, command_info = Cacli.run_command(
                    command_args=['cacli', 'network-policy', 'delete', '-n', policy_name])

            assert status == 0, "delete_network_policy command failed with error {0}-{1}".format(status, command_info)

    class IngressNetworkPolicy(object):
        @staticmethod
        def file_handler(np: dict, command: str):
            temp_file = tempfile.NamedTemporaryFile(mode='w+')
            np_json = json.dumps(np, indent=2)
            Logger.logger.info("ingress policy json:\n{}".format(str(np_json)))
            temp_file.write(np_json)
            temp_file.flush()
            command_args = ['cacli', 'ingress-policy', command, '-i', temp_file.name]
            Cacli.IngressNetworkPolicy.run_command(command_args=command_args)
            temp_file.close()
            # os.remove(temp_file.name)

        @staticmethod
        def command_handler(policy_args, command: str):
            command_args = ['cacli', 'ingress-policy', command, '-n', policy_args.name]
            [command_args.extend(i) for i in [['-s-wlid', i] for i in policy_args.server_wlid]]
            [command_args.extend(i) for i in [['-c-wlid', i] for i in policy_args.client_wlid]]
            [command_args.extend(i) for i in
             [['-s-att', "{}={}".format(k, v)] for k, v in policy_args.server_attributes.items()]]
            [command_args.extend(i) for i in
             [['-c-att', "{}={}".format(k, v)] for k, v in policy_args.client_attributes.items()]]
            [command_args.extend(i) for i in [['-svc', i] for i in policy_args.k8s_service]]
            [command_args.extend(i) for i in [['-s-port', str(i)] for i in policy_args.server_port]]
            [command_args.extend(i) for i in [['-svc-port', str(i)] for i in policy_args.k8s_service_port]]

            command_args.extend(['--enforcementAction', policy_args.enforcement_action])
            command_args.extend(['--permissions', policy_args.permissions])
            command_args.extend(['--policy_type', policy_args.policy_type])
            if policy_args.permissive_mode:
                command_args.extend(['--permissive_mode'])

            Cacli.IngressNetworkPolicy.run_command(command_args=command_args)

        @staticmethod
        def create(policy_args):
            policy_args.update_np()
            if policy_args.np:
                Cacli.IngressNetworkPolicy.file_handler(np=policy_args.np, command="create")
            else:
                Cacli.IngressNetworkPolicy.command_handler(policy_args=policy_args, command="create")

        @staticmethod
        def update(policy_args):
            policy_args.update_np()
            if policy_args.np:
                Cacli.IngressNetworkPolicy.file_handler(np=policy_args.np, command="update")
            else:
                Cacli.IngressNetworkPolicy.command_handler(policy_args=policy_args, command="update")

        @staticmethod
        def run_command(command_args: list):
            status, command_info = Cacli.run_command(command_args=command_args)
            assert status == 0, "update_ingress_policy command failed with error {0}-{1}".format(status, command_info)

        @staticmethod
        def delete(policy_id=None, policy_name=None):
            if policy_id:
                status, command_info = Cacli.run_command(
                    command_args=['cacli', 'ingress-policy', 'delete', '-id', policy_id])
            else:
                status, command_info = Cacli.run_command(
                    command_args=['cacli', 'ingress-policy', 'delete', '-n', policy_name])

            assert status == 0, "delete_ingress_policy command failed with error {0}-{1}".format(status, command_info)

    class EncryptionConfiguration(object):
        @staticmethod
        def create(encryption_config):
            temp_file = CacliUtils.store_in_temp_file(encryption_config.get())
            command_args = ['cacli', 'encryption-configuration', 'create', '--input', temp_file.name]
            status, command_info = Cacli.run_command(command_args=command_args)
            CacliUtils.remove_temp_file(temp_file)
            assert status == 0, "post_workload_encryption_configuration command failed with error {0}-{1}".format(
                status, command_info)

        @staticmethod
        def update(encryption_config):
            temp_file = CacliUtils.store_in_temp_file(encryption_config.get())
            command_args = ['cacli', 'encryption-configuration', 'add', '--input', temp_file.name]
            status, command_info = Cacli.run_command(command_args=command_args)
            CacliUtils.remove_temp_file(temp_file)
            assert status == 0, "post_workload_encryption_configuration command failed with error {0}-{1}".format(
                status,
                command_info)

        @staticmethod
        def delete(wlid: str):
            status, command_info = Cacli.run_command(
                command_args=['cacli', 'encryption-configuration', 'delete', '-wlid', wlid])

            assert status == 0, "delete_workload_encryption_configuration command failed with error {0}-{1}".format(
                status,
                command_info)

    class Secret(object):
        @staticmethod
        def encrypt(sid):
            returncode, return_obj = Cacli.run_command(['cacli', 'secret', 'encrypt', '-sid', sid])
            assert returncode == 0, 'encrypt command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                           return_obj.stderr)

        @staticmethod
        def get(sid: str):
            command = ['cacli', 'secret', 'get', '-sid', sid]
            returncode, return_obj = Cacli.run_command(command)
            assert returncode == 0, 'get command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)
            return CacliUtils().convert_json_response_to_dict(return_obj.stdout)

        @staticmethod
        def decrypt(sid: str):
            returncode, return_obj = Cacli.run_command(['cacli', 'secret', 'decrypt', '-sid', sid])
            assert returncode == 0, 'decrypt command failed. code: {}\nmessage: {}'.format(
                returncode, return_obj.stderr)

        def list(self):
            returncode, return_obj = Cacli.run_command(['cacli', 'secret', 'list'])
            assert returncode == 0, 'list command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                        return_obj.stderr)
            return CacliUtils().convert_literal_response_to_list(return_obj.stdout)

    class SecretPolicy(object):
        @staticmethod
        def create(secret_policy=None, sid: str = None):
            # create signing profile
            if secret_policy:
                temp_file = None
                if isinstance(secret_policy, dict):
                    temp_file = CacliUtils().store_in_temp_file(secret_policy)
                    secret_policy = temp_file.name
                assert isfile(secret_policy), "secret policy not found at {}".format(secret_policy)
                returncode, return_obj = Cacli.run_command(['cacli', 'secp', 'create', '-i', secret_policy])
                CacliUtils().remove_temp_file(temp_file)
            else:
                returncode, return_obj = Cacli.run_command(['cacli', 'secp', 'create', '-sid', sid])

            assert returncode == 0, 'create command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)

        @staticmethod
        def get(name: str = '', sid: str = ""):
            command = ['cacli', 'secp', 'get']
            if name != '':
                command.extend(['-n', name])
            if sid != '':
                command.extend(['-sid', sid])
            returncode, return_obj = Cacli.run_command(command, display_stdout=False)
            assert returncode == 0, 'get command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)
            return CacliUtils().convert_json_response_to_dict(return_obj.stdout)

        @staticmethod
        def delete(name: str = "", sid: str = ""):
            command = ['cacli', 'secp', 'delete']
            if name != '':
                command.extend(['-n', name])
            if sid != '':
                command.extend(['-sid', sid])
            returncode, return_obj = Cacli.run_command(command)
            assert returncode == 0, 'delete command failed. code: {}\nmessage: {}'.format(
                returncode, return_obj.stderr)

        def list(self):
            returncode, return_obj = Cacli.run_command(['cacli', 'secp', 'list'])
            assert returncode == 0, 'list command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                        return_obj.stderr)
            return CacliUtils().convert_literal_response_to_list(return_obj.stdout)

        @staticmethod
        def encrypt(input: str = None, output: str = None, message: str = None, input_base64: bool = False,
                    output_base64: bool = False, split: bool = False):
            # create signing profile
            command = ['cacli', 'secp', 'encrypt']
            if input:
                command.extend(["-i", input])
            if output:
                command.extend(["-o", output])
            if message:
                command.append(["-m", message])
            if input_base64:
                command.append("-ib64")
            if output_base64:
                command.append("-ob64")
            if split:
                command.append("--split")
            returncode, return_obj = Cacli.run_command(command)
            assert returncode == 0, 'create command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)
            return return_obj.stdout.decode().rstrip("\n")

    class WorkloadTemplate(object):

        def create(self, workload_template):
            """
            :param workload_template: str or dict.
                str: path to workloadTemplate file
                dict: workloadTemplate as a dict
            """
            if isinstance(workload_template, dict):
                temp_file = CacliUtils.store_in_temp_file(workload_template)
                r = self.create_or_update_actions(temp_file.name, 'create')
                CacliUtils.remove_temp_file(temp_file)
                return r
            elif isinstance(workload_template, str):
                return self.create_or_update_actions(workload_template, 'create')

        def update(self, workload_template=None, wlid: str = None, sp_name: str = None, container_name: str = None):
            """
            :param workload_template: str or dict.
                str: path to workloadTemplate file
                dict: workloadTemplate as a dict
            :param wlid:
            :param sp_name:
            :param container_name:
            """
            if workload_template:
                if isinstance(workload_template, dict):
                    temp_file = CacliUtils().store_in_temp_file(temp_dict=workload_template)
                    r = self.create_or_update_actions(temp_file.name, 'update')
                    CacliUtils().remove_temp_file(temp_file)
                elif isinstance(workload_template, str):
                    return self.create_or_update_actions(workload_template, 'update')
            else:
                command = ['cacli', 'wt', 'update']
                if wlid:
                    command.extend(['-wlid', wlid])
                if sp_name:
                    command.extend(['-sp', sp_name])
                if container_name:
                    command.extend(['--container', container_name])
                returncode, return_obj = Cacli.run_command(command)
                assert returncode == 0, 'update command failed. code: {}\nmessage: {}'.format(
                    returncode, return_obj.stderr)
                return CacliUtils().convert_json_response_to_dict(return_obj.stdout)

        @staticmethod
        def get(wlid: str = ''):
            command = ['cacli', 'wt', 'get']
            if wlid != '':
                command.extend(['-wlid', wlid])
            returncode, return_obj = Cacli.run_command(command)
            assert returncode == 0, 'get command failed. code: {}\nmessage: {}'.format(
                returncode, return_obj.stderr)
            return CacliUtils().convert_json_response_to_dict(return_obj.stdout)

        @staticmethod
        def delete(wlid: str):
            returncode, return_obj = Cacli.run_command(
                ['cacli', 'wt', 'delete', '-wlid', wlid])
            assert returncode == 0, 'delete command failed. code: {}\nmessage: {}'.format(
                returncode, return_obj.stderr)

        @staticmethod
        def download(wlid: str, save_in_path: str = '.'):
            returncode, return_obj = Cacli.run_command(
                ['cacli', 'wt', 'download', '-wlid', wlid, '-o', save_in_path])
            assert returncode == 0, 'download command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                            return_obj.stderr)

        @staticmethod
        def list():
            returncode, return_obj = Cacli.run_command(['cacli', 'wt', 'list'])
            assert returncode == 0, 'download command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                            return_obj.stderr)
            return CacliUtils().convert_literal_response_to_list(return_obj.stdout)

        @staticmethod
        def triplet(wlid: str):
            returncode, return_obj = Cacli.run_command(
                ['cacli', 'wt', 'triplet', '-wlid', wlid])
            assert returncode == 0, 'download command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                            return_obj.stderr)
            return CacliUtils().convert_json_response_to_dict(return_obj.stdout)

        @staticmethod
        def sign(wlid: str, container_name: str = None):
            command = ['cacli', 'wt', 'sign', '-wlid', wlid]
            if container_name:
                command.extend(['-c', container_name])
            returncode, return_obj = Cacli.run_command(command_args=command, timeout=360)
            assert returncode == 0, 'sign command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stdout)

        @staticmethod
        def create_or_update_actions(path_to_workload_template: str, command: str):
            # create workload template
            assert isfile(path_to_workload_template), "workload template not found at {}".format(
                path_to_workload_template)
            returncode, return_obj = Cacli.run_command(['cacli', 'wt', command, '-i', path_to_workload_template])
            assert returncode == 0, 'create command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)
            response = CacliUtils().convert_json_response_to_dict(return_obj.stdout)
            assert 'wlid' in response, "wlid not found in 'create' command response. response: {}".format(response)
            return response['wlid']

    class EnforcementPolicy(object):
        @staticmethod
        def create(enforcement_policy: any):
            # create enforcement profile
            temp_file = None
            if isinstance(enforcement_policy, dict):
                temp_file = CacliUtils().store_in_temp_file(enforcement_policy)
                enforcement_policy = temp_file.name
            assert isfile(enforcement_policy), "enforcement policy not found at {}".format(enforcement_policy)
            returncode, return_obj = Cacli.run_command(['cacli', 'en', 'create', '-i', enforcement_policy])
            CacliUtils().remove_temp_file(temp_file)

            assert returncode == 0, 'create command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)

        @staticmethod
        def convert(enforcement_config=None):
            # create enforcement profile
            if enforcement_config:
                temp_file = None
                if isinstance(enforcement_config, dict):
                    temp_file = CacliUtils().store_in_temp_file(enforcement_config)
                    enforcement_config = temp_file.name
                assert isfile(enforcement_config), "enforcement config not found at {}".format(enforcement_config)
                returncode, return_obj = Cacli.run_command(['cacli', 'en', 'convert', '-i', enforcement_config])
                CacliUtils().remove_temp_file(temp_file)
            else:
                returncode, return_obj = Cacli.run_command(['cacli', 'en', 'create'])

            assert returncode == 0, 'create command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)

    class SigningProfile(object):
        @staticmethod
        def create(signing_profile):
            # create signing profile
            temp_file = None
            if isinstance(signing_profile, dict):
                temp_file = CacliUtils().store_in_temp_file(signing_profile)
                signing_profile = temp_file.name
            assert isfile(signing_profile), "signing profile not found at {}".format(signing_profile)
            returncode, return_obj = Cacli.run_command(['cacli', 'sp', 'create', '-i', signing_profile])
            CacliUtils().remove_temp_file(temp_file)
            assert returncode == 0, 'create command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)

        @staticmethod
        def get(name: str = ''):
            command = ['cacli', 'sp', 'get']
            if name != '':
                command.extend(['-n', name])
            returncode, return_obj = Cacli.run_command(command)
            assert returncode == 0, 'get command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)
            return CacliUtils().convert_json_response_to_dict(return_obj.stdout)

        @staticmethod
        def generate(wlid: str, container_name: str = None, signingprofile_name: str = None):
            command = ['cacli', 'sp', 'generate', '-wlid', wlid]
            if container_name:
                command.extend(["--container_name", container_name])
            if signingprofile_name:
                command.extend(['--signingprofile_name', signingprofile_name])
            returncode, return_obj = Cacli.run_command(command)
            assert returncode == 0, 'get command failed. code: {}\nmessage: {}'.format(returncode, return_obj.stderr)
            return CacliUtils().convert_json_response_to_dict(return_obj.stdout)

        @staticmethod
        def delete(name: str):
            returncode, return_obj = Cacli.run_command(
                ['cacli', 'sp', 'delete', '-n', name])
            assert returncode == 0, 'delete command failed. code: {}\nmessage: {}'.format(
                returncode, return_obj.stderr)

        def list(self):
            returncode, return_obj = Cacli.run_command(['cacli', 'sp', 'list'])
            assert returncode == 0, 'list command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                        return_obj.stderr)
            return CacliUtils().convert_literal_response_to_list(return_obj.stdout)

    class SigningConfiguration(object):
        @staticmethod
        def download(wlid: str, container_name: str, save_in_path: str = '.'):
            returncode, return_obj = Cacli.run_command(
                ['cacli', 'sc', 'download', '-wlid', wlid, '-o', save_in_path, '-n', container_name])
            assert returncode == 0, 'download command failed. code: {}\nmessage: {}'.format(returncode,
                                                                                            return_obj.stderr)

    @staticmethod
    def run_command(command_args, timeout=60, display_stdout: bool = True):
        return TestUtil.run_command(command_args=command_args, timeout=timeout, display_stdout=display_stdout)


class CacliUtils(object):

    def convert_json_response_to_dict(self, json_in_bytes_format: bytes):
        json_in_str_format = json_in_bytes_format.decode("utf-8")
        f, e = self.find_curly_braces(json_in_str_format)
        assert f >= 0 and e >= 0, 'response. response: {}'.format(
            json_in_str_format)
        return json.loads(json_in_str_format[f:e])

    def convert_literal_response_to_list(self, json_in_bytes_format: bytes):
        json_in_str_format = json_in_bytes_format.decode("utf-8")
        f, e = self.find_braces(json_in_str_format)
        assert f >= 0 and e >= 0, 'response. response: {}'.format(
            json_in_str_format)
        return ast.literal_eval(json_in_str_format[f:e])

    def convert_literal_response_to_dict(self, literal_in_bytes_format: bytes):
        literal_in_str_format = literal_in_bytes_format.decode("utf-8")
        f, e = self.find_curly_braces(literal_in_str_format)
        assert f >= 0 and e >= 0, 'response. response: {}'.format(
            literal_in_str_format)
        return ast.literal_eval(literal_in_str_format[f:e])

    @staticmethod
    def find_curly_braces(json_in_str_format):
        return json_in_str_format.find('{'), len(json_in_str_format) - json_in_str_format[::-1].find('}')

    @staticmethod
    def find_braces(json_list_in_str_format):
        return json_list_in_str_format.find('['), len(json_list_in_str_format) - json_list_in_str_format[::-1].find(']')

    @staticmethod
    def store_in_temp_file(temp_dict: dict):
        temp_file = tempfile.NamedTemporaryFile(mode='w+')
        json_str = json.dumps(temp_dict, indent=4)
        json_str = json_str.replace("True", "true")
        json_str = json_str.replace("None", "null")
        temp_file.write(json_str)
        temp_file.flush()
        return temp_file

    @staticmethod
    def remove_temp_file(temp_file):
        if not temp_file:
            return
        try:
            temp_file.close()
        except Exception as e:
            Logger.logger.info("while removing tmp file: {}".format(e))

    # @staticmethod
    # def dump_to_file(data):
    #     fd, temp_file_path = tempfile.mkstemp(text=True)
    #     temp_file = os.fdopen(fd, "w")
    #     if isinstance(data, dict):
    #         data = json.dumps(data)
    #     temp_file.write(data)
    #     temp_file.flush()
    #     temp_file.close()
    #     return temp_file_path
    #
    # @staticmethod
    # def remove_file(temp_file_path):
    #     os.remove(temp_file_path)
