import os
import shutil
import tempfile
import time

import docker

from infrastructure import scapy_wrapper
from systest_utils import Logger, TestUtil
from systest_utils.ports import *
import humanize


# NOTE: all the 'services' in here are docker services (not caportal services nor dashboard services)
class DockerRunArgs(object):
    def __init__(self, **args):
        # TODO
        self.command = args['command'] if 'command' in args else list()
        self.environment: list = args['environment'] if 'environment' in args else list()
        self.ulimits: list = args['ulimits'] if 'ulimits' in args else list()
        self.ports = args['ports'] if 'ports' in args else dict()
        self.volumes = args['volumes'] if 'volumes' in args else dict()
        self.network = args['network'] if 'network' in args else None
        self.detach = args['detach'] if 'detach' in args else True
        self.name = args['name'] if 'name' in args else ""
        self.extra_hosts = args['extra_hosts'] if 'extra_hosts' in args else dict()
        self.mem_limit = args['mem_limit'] if 'mem_limit' in args else "3g"
        self.cap_add = []  # ['SYS_ADMIN', 'SYS_PTRACE']

    def set_name(self, name: str):
        self.name = name

    def set_network(self, network):
        self.network = network

    def set_general_caa_environment_params(self, caa_home):
        self.environment.append("CAA_ENABLE_DISCOVERY=1")
        self.environment.append('CAA_HOME={}'.format(caa_home))
        self.environment.append('LD_PRELOAD={}'.format(os.path.join(caa_home, 'libcaa.so')))
        self.environment.append('CAA_USE_PROCESS_AT=1')
        self.environment.append('CAA_ENABLE_HOOK_TUNNEL=1')
        self.environment.append('CAA_ENABLE_CRASH_REPORTER=1')

    def set_general_caa_volume_params(self):
        self.volumes[os.path.join(os.getcwd(), 'resources', 'ld.so.txt')] = {"bind": '/etc/ld.so.preload', "mode": 'rw'}

    def set_container_caa_environment_params(self, process, container_name: str, img: str):
        if isinstance(process, str):
            caa_loadnames = 'CAA_LOADNAMES={}'.format(process)
        elif isinstance(process, list):
            caa_loadnames = 'CAA_LOADNAMES={}'.format(','.join(process))
        else:
            caa_loadnames = 'CAA_LOADNAMES=*'

        self.environment.append(caa_loadnames)
        self.environment.append('CAA_CONTAINER_NAME={}'.format(container_name))
        self.environment.append('CAA_CONTAINER_IMAGE_NAME={}'.format(img))

    def add_container_command_params(self, command_line):
        self.command.extend(command_line)

    def set_container_caa_volume_params(self, container_name, caa_home, tmpdir):
        self.volumes[os.path.join(tmpdir, container_name)] = {"bind": caa_home, "mode": 'rw'}

    def add_environment(self, k, v):
        self.environment.append('{}={}'.format(k, v))

    def update_sub_key_environment(self, sub_key: str, v: str):
        for i, env in enumerate(self.environment):
            k = env.split("=")[0]
            if sub_key in k:
                self.environment[i] = "{}={}".format(k, v)

    def update_environment(self, key: str, v: str):
        for i, env in enumerate(self.environment):
            k = env.split("=")[0]
            if key == k:
                self.environment[i] = "{}={}".format(k, v)
                return
        self.environment.append("{}={}".format(key, v))

    def add_volume(self, src: str, dest: str):
        if not os.path.isabs(src) or not os.path.isabs(dest):
            raise Exception("volume path must be absolute path. receive paths: src- {}, dest- {}".format(src, dest))
        self.volumes[src] = {"bind": dest, "mode": 'rw'}

    def set_ports(self, docker_c, img):
        published_ports = list()
        if 'ExposedPorts' in docker_c.images.get(img).attrs['Config']:
            published_ports = [int(port_desc.split('/')[0]) for port_desc in
                               docker_c.images.get(img).attrs['Config']['ExposedPorts']]

        if len(published_ports) == 0:
            self.ports[HTTP_PORT] = None  # next(self.available_ports)
            self.ports[HTTPS_PORT] = None  # next(self.available_ports)
            self.ports[MONGO_PORT1] = None  # next(self.available_ports)
            self.ports[MONGO_PORT2] = None  # next(self.available_ports)
            self.ports[MYSQL_PORT] = None  # next(self.available_ports)
            self.ports[ELASTIC_PORT1] = None  # next(self.available_ports)
            self.ports[ELASTIC_PORT2] = None  # next(self.available_ports)
            self.ports[REDIS_PORT] = None  # next(self.available_ports)
            self.ports[SCALITY_PORT] = None  # next(self.available_ports)
        else:
            for port in published_ports:
                if not port in self.ports:
                    self.ports[port] = None

    def update(self, docker_run_args):
        self.command = list(set(self.command + docker_run_args.command))
        self.environment = list(set(self.environment + docker_run_args.environment))
        self.ulimits.extend(docker_run_args.ulimits)
        self.cap_add = list(set(self.cap_add + docker_run_args.cap_add))

        self.ports.update(docker_run_args.ports)
        self.volumes.update(docker_run_args.volumes)


class DockerWrapper(object):
    api_client = None
    try:        
        api_client = docker.APIClient()
    except Exception as ex:
        print("docker sock not found. only non-docker tests are allowed", ex)    

    def __init__(self):
        self.docker_client = None
        try:
            self.docker_client = docker.DockerClient()
        except Exception as ex:
            print("docker sock not found. only non-docker tests are allowed", ex)

        # tcp
        self._tcp_dump_img = 'kaazing/tcpdump:latest'
        self._dns_server_img = 'defreitas/dns-proxy-server:latest'
        self._resolv_conf_backup = os.path.join(os.getcwd(), 'resolv.conf.backup')

    def build_image(self, image, docker_file):
        build_args = dict()

        build_args['path'] = os.path.sep.join(docker_file.split(os.path.sep)[:-1])
        build_args['dockerfile'] = docker_file.split(os.path.sep)[-1]
        build_args['tag'] = image
        build_args['timeout'] = 120

        self.docker_client.images.build(**build_args)

    def download_image(self, image: str, docker_file: str = None, update=True):
        # TODO check docker file exists
        # check if image exists and create it if required
        Logger.logger.debug("Updating image: {}".format(update))
        if not docker_file:
            fd, d_file = tempfile.mkstemp(dir=os.getcwd(), text=True)
            temp_file = os.fdopen(fd, "w")
            temp_file.write("FROM {}".format(image))
            temp_file.flush()
        else:
            d_file = TestUtil.is_abs_path(docker_file)
        if update:
            self.remove_image(image)
            self.build_image(image, d_file)
        else:
            try:
                self.docker_client.images.get(image)
                Logger.logger.debug("image {} found".format(image))
            except:
                Logger.logger.debug("building image {}".format(image))
                self.build_image(image, d_file)
            finally:
                if not docker_file:
                    os.remove(d_file)

    def download_images(self, images: dict, update=True):
        for image, docker_file in images.items():
            self.download_image(image=image, docker_file=docker_file, update=update)

    def remove_image(self, tag: str):
        try:
            image = self.docker_client.images.get(name=tag)
            self.docker_client.images.remove(image=image.short_id, force=True)
        except Exception as e:
            Logger.logger.debug(e)

    def run_container(self, image, run_args: DockerRunArgs = DockerRunArgs(), remove_running_container=False):
        # run container
        container_is_running = False
        # container_timeout = threading.Thread(target=container_run_timeout, args=(60, lambda: container_is_running))
        # container_timeout.start()
        Logger.logger.debug(f"{self.run_command_display(image=image, **TestUtil.get_class_members(run_args))}")
        container = self.docker_client.containers.run(image=image, **TestUtil.get_class_members(run_args))
        container_is_running = True
        if not isinstance(container, docker.models.containers.Container):
            raise Exception('can\'t start new container reason: {}'.format(container))
        return container

    def remove_container_by_name(self, container_name: str, remove_volume=True):
        containers = self.docker_client.containers.list(filters={"name": container_name}, all=True)
        for i in containers:
            i.stop()
            i.remove(v=remove_volume)

    def docker_exec(self, container, command: str):
        container.exec_run(command)

    @staticmethod
    def run_command_display(image: str
                            , name: str = None
                            , environment: list = None
                            , volumes: dict = None
                            , mem_limit: str = None
                            , network: str = None
                            , ports: dict = None
                            , cap_add: list = None
                            , detach: bool = False
                            , command: list = None
                            , **kwargs):
        run_command = f"docker run"
        if name:
            run_command += f' --name="{name}"'
        if environment:
            run_command += " " + " ".join([f'-e "{i}"' for i in environment])
        if volumes:
            run_command += " " + " ".join([f'-v "{i}:{j["bind"]}"' for i, j in volumes.items()])
        if ports:
            run_command += " " + " ".join([f'-p "{j}:{i}"' for i, j in ports.items()])
        if mem_limit:
            run_command += f' --memory="{mem_limit}"'
        if network:
            run_command += f' --network="{network}"'
        if cap_add:
            run_command += " " + " ".join([f'--cap-add="{i}"' for i in cap_add])
        if detach:
            run_command += " -d"

        run_command += " " + image
        if command:
            run_command += " " + " ".join(command)
        return run_command

    @staticmethod
    def get_container_ip(container, bridge=None):
        if bridge is None:
            bridge = 'bridge'
        ins_dict = DockerWrapper.inspect(container=container)
        return ins_dict['NetworkSettings']['Networks'][bridge]['IPAddress']

    @staticmethod
    def inspect(container):
        return DockerWrapper.api_client.inspect_container(container.id)

    def start_network(self, network_name, network_subnet=None):
        err = ''
        # for i in range(5):
        #     try:
        # driver=driver,
        # network_subnet = network_subnet if network_subnet else '172.{}.0.0/16'.format(random.randint(16, 31))
        # ipam_config = docker.types.IPAMConfig(pool_configs=[docker.types.IPAMPool(subnet=network_subnet)])
        return self.docker_client.networks.create(name=network_name, attachable=True)  # , ipam=ipam_config)
        #         return network
        #     except Exception as e:
        #         err = e
        # raise Exception('can\'t start new network. reason: {}'.format(err))

    @staticmethod
    def exit_network(network):
        try:
            network.remove()
        except Exception as e:
            Logger.logger.warning(e)

    def get_container_by_name(self, container_name: str):
        containers = self.docker_client.containers.list(filters={"name": container_name}, all=True)
        if containers == 0:
            raise Exception(f"no containers found matching name '{container_name}'")
        return containers[0]

    def get_container_stats(self, container_name: str):
        container = self.get_container_by_name(container_name=container_name)
        return container.stats(stream=False)

    @staticmethod
    def calculate_container_cpu_percentage(docker_stats: dict):
        # https://github.com/moby/moby/blob/28a7577a029780e4533faf3d057ec9f6c7a10948/api/client/stats.go#L309
        cpu_count = len(docker_stats["cpu_stats"]["cpu_usage"]["percpu_usage"])
        cpu_delta = float(docker_stats["cpu_stats"]["cpu_usage"]["total_usage"]) - float(
            docker_stats["precpu_stats"]["cpu_usage"]["total_usage"])
        system_delta = float(docker_stats["cpu_stats"]["system_cpu_usage"]) - float(
            docker_stats["precpu_stats"]["system_cpu_usage"])
        return cpu_delta / system_delta * 100.0 * cpu_count if system_delta > 0.0 else 0.0

    @staticmethod
    def get_container_memory_statistics(docker_stats: dict):
        # https://github.com/moby/moby/blob/28a7577a029780e4533faf3d057ec9f6c7a10948/api/client/stats.go#L69
        usage = docker_stats["memory_stats"]["usage"]
        limit = docker_stats["memory_stats"]["limit"]
        # max_usage = docker_stats["memory_stats"]["max_usage"]
        percentage = usage / limit * 100
        return humanize.naturalsize(usage), humanize.naturalsize(limit), percentage


class DockerTcpDumper(object):
    """
    Cyber Armor Docker utils object.
    """

    _tcp_dump_img = 'kaazing/tcpdump:latest'
    _dns_server_img = 'defreitas/dns-proxy-server:latest'

    def __init__(self):
        super(DockerTcpDumper, self).__init__()
        self.client = docker.DockerClient()
        self.has_dns = False
        self._dns = {}
        self._tcp_dumpers = {}

    def run_tcp_dumper(self, *hosts):
        Logger.logger.debug("Creating tcp dumper container")
        pcap = self.start_tcp_dumper()
        fltr = {'src_ips': hosts, 'dst_ips': hosts}
        return [scapy_wrapper.ScapyWrapper.is_pcap_file_encrypted(pcap, fltr=fltr)]

    def start_dns_server(self):
        """
        Start DNS server container that allows you
        get to the containers hostnames from host machine (only on Linux).

        Return value:
            The 'docker python API' container of the dns server (Container).
        """

        if not self.has_dns:
            # Backup old /etc/resolv.conf
            self._dns['backup_path'] = os.path.join(
                os.getcwd(), 'resolv.conf.backup')
            shutil.copyfile("/etc/resolv.conf", self._dns['backup_path'])

            # Start the DNS server
            volumes = {}
            volumes["/var/run/docker.sock"] = {
                "bind": "/var/run/docker.sock", "mode": 'rw'}
            volumes["/etc/resolv.conf"] = {
                "bind": "/etc/resolv.conf", "mode": 'rw'}

            container = self.client.containers.run(
                self._dns_server_img, volumes=volumes, detach=True)

            if not isinstance(container, docker.models.containers.Container):
                raise Exception('can\'t start new dns server container reason: {}'.format(container))
            self._dns['container'] = container

            self.has_dns = True
        else:
            container = self._dns['container']

        return container

    def stop_dns_server(self):
        """
        Stop DNS server container that started via DockerUtils.start_dns_server.
        """
        if not self._dns:
            return

        # Stop the running DNS Server container
        self._dns['container'].remove(force=True)

        # Restore old /etc/resolv.conf.
        # For writing to /etc/resolv.conf we need root privileges,
        # so we do it inside a container (the docker service run as root..)
        volumes = dict()
        volumes["/etc/resolv.conf"] = {"bind": "/etc/resolv.conf", "mode": 'rw'}
        volumes[self._dns['backup_path']] = {"bind": "/tmp/testrunner", "mode": 'rw'}

        self.client.containers.run(image=self._dns_server_img, volumes=volumes,
                                   command=["cp", "/tmp/testrunner/resolv.conf.backup", "/etc/resolv.conf"],
                                   remove=True, detach=False)
        self._dns = {}

    def start_tcp_dumper(self, network='host', path=None, hosts_fltr=[]):
        """
        Start dumping the tcp traffic of a Docker Network.

        Parameters:
            network: The name or the id of the network, or a 'docker python API' network object.
            path: path for the pcap outpt file (optionally).
            hosts_fltr: e.g. ['1.2.3.4']}

        Return value:
            The pcap file path.
        """
        if isinstance(network, str):
            network = self.client.networks.get(network)

        os.makedirs(os.path.join(os.getcwd(), 'tcp_dump'), exist_ok=True)

        if network.short_id not in self._tcp_dumpers:
            if 'dir' not in self._tcp_dumpers:
                dump_dir = os.path.join(os.getcwd(), 'tcp_dump')
                os.mkdir(dump_dir) if not os.path.exists(dump_dir) else None
                self._tcp_dumpers['dir'] = dump_dir
            if path:
                net_dir = path
            else:
                net_dir = os.path.join(self._tcp_dumpers['dir'], network.short_id)
                os.mkdir(net_dir) if not os.path.exists(net_dir) else None

            os.rename(os.path.join(net_dir, 'tcpdump.pcap'),
                      os.path.join(net_dir, 'tcpdump-{}.pcap'.format(time.time()))) if os.path.exists(
                os.path.join(net_dir, 'tcpdump.pcap')) else None

            cmd = '-C 1000 -v -i any -w /tcpdump/tcpdump.pcap'
            if hosts_fltr:
                src = 'src ' + ' or src '.join(hosts_fltr)
                dst = 'dst ' + ' or dst '.join(hosts_fltr)
                cmd += ' ({}) and ({})'.format(src, dst)

            vol = {net_dir: {'bind': '/tcpdump', 'mode': 'rw'}}
            container = self.client.containers.run(self._tcp_dump_img, network=network.name, remove=True, volumes=vol,
                                                   detach=True, command=cmd)
            if not (type(container) is docker.models.containers.Container):
                os.rmdir(net_dir) if not os.path.exists(net_dir) else None
                raise Exception(
                    'can\'t start new dns server container reason: {}'.format(container))

            self._tcp_dumpers[network.short_id] = {
                'container': container, 'pcap_dir': net_dir}

        return os.path.join(self._tcp_dumpers[network.short_id]['pcap_dir'], 'tcpdump.pcap')

    def stop_tcp_dumper(self, network='host'):
        """
        Stop dumping the tcp traffic of a Docker Network that has been
        started by self.start_tcp_dump.

        Parameters:
            network: The name or the id of the network, or a 'docker python API' network object.

        Return value:
            The pcap file path.
        """
        if type(network) == str:
            network = self.client.networks.get(network)

        if network.short_id in self._tcp_dumpers:
            self._tcp_dumpers[network.short_id]['container'].remove(force=True, v=True)

        pcap_path = os.path.join(
            self._tcp_dumpers[network.short_id]['pcap_dir'], 'tcpdump.pcap')
        del self._tcp_dumpers[network.short_id]

        return pcap_path

    def stop_all_tcp_dumpers(self):
        tmp = dict(self._tcp_dumpers)
        for key in tmp:
            if key != 'dir':
                self.stop_tcp_dumper(key)
        if os.path.exists(os.path.join(os.getcwd(), 'tcp_dump')):
            shutil.rmtree(os.path.join(os.getcwd(), 'tcp_dump'))

    def get_service_running_container(self, service):
        for task in service.tasks():
            if task['DesiredState'] == 'running':
                container_id = task['Status']['ContainerStatus']['ContainerID']
                return self.client.containers.get(container_id)

    @staticmethod
    def close_networks(networks):
        """
        Try to close and remove a list of docker netowrks, return list of networks that
        refused to be removed.

        Parameters:
            networks: a list of instance of 'docker python API' networks.

        Return value:
            A list of networks that refused to be removed (on success, it should be empty) (list).
        """
        remain_networks = list(networks)
        for network in networks:
            try:
                network.remove()
                remain_networks.remove(network)
            except:
                pass

        return remain_networks

    @staticmethod
    def test_tcp_encryption(tcp_dumper):
        if not tcp_dumper:
            return
        Logger.logger.info("testing tcp tunneling")
        for tcp_checker in tcp_dumper:
            assert next(tcp_checker), 'TCP traffic is not encrypted well'
        Logger.logger.info('Successfully tested tcp tunneling')
