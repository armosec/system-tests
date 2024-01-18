import json
import socket
import time
from random import randint
from threading import Thread
from systest_utils.statics import Statistics
from systest_utils.wlid import Wlid

from infrastructure import docker_wrapper
from infrastructure.thread_wrapper import ThreadSignal
from systest_utils import systests_utilities, container_logs_handler, Logger, TestUtil, statics
from tests_scripts import base_test
import os

LIN_CAA_HOME = "/etc/cyberarmor"
MEMORY = "MEMORY"
CPU = "CPU"


class BaseDockerizeTest(base_test.BaseTest):
    def __init__(self, **kwargs):
        super().__init__(test_driver=kwargs['test_driver'], backend=kwargs['backend'],
                         test_obj=kwargs['test_obj'])
        self.docker: docker_wrapper.DockerWrapper = docker_wrapper.DockerWrapper()

        # if container replica > 1, replicate wt containers
        self.replicate_wt_containers()

        # use in cleanup
        self.containers: list = list()
        self.networks: list = list()
        self.tcp_dumper = None
        self.remove_containers_on_cleanup = True  # remove containers on cleanup
        self.container_statistics = {}

    @staticmethod
    def get_test_images(workload_templates):
        images = {}
        if not isinstance(workload_templates, list):
            workload_templates = [workload_templates]
        for i in workload_templates:
            containers = i.containers
            if not isinstance(containers, list):
                containers = [containers]
            for j in containers:
                images[j.image_tag] = j.dockerfile
        return images

    def __del__(self):
        super(BaseDockerizeTest, self).__del__()

    def cleanup(self, ignore_agent=False, ignore_containers_logs: bool = False,
                **kwargs):
        agent_stat, summary = "", ""
        self.test_summery_data.update(self.container_statistics)        

        if not ignore_containers_logs:
            # remove docker containers
            try:
                agent_stat, cont_res, summary = self.read_logs(self.containers)
                Logger.logger.debug(cont_res)
            except Exception as e:
                Logger.logger.error(e)

        super().cleanup(**kwargs)
        return agent_stat, summary

    def read_logs(self, containers=None):
        # TODO: separate reading logs and test status
        """remove a list of containers and return their logs as a string"""
        if not containers:
            return statics.FAILURE, "no containers found", "no containers found"

        logs = "\n{line}\n{part_line} Beginning Of Docker Logs {part_line}\n{line}".format(line='=' * 150,
                                                                                           part_line='=' * 62)
        containers = containers[::-1] if isinstance(containers, list) else [containers]
        agent_status = statics.SUCCESS
        summary = ""
        if len(containers) < 1:
            return statics.FAILURE, "no containers found", "no containers found"

        for container in containers[:]:
            # logs recorder
            test_name = container.image.tags[0].split(':')[0] if len(container.image.tags) > 0 else container.name
            agent_log_parser = container_logs_handler.AgentLogParser(
                container=container)
            logs += self.parse_test_logs(container,
                                         agent_log_parser, test_name)
            summary += self.set_agent_summery(agent_log_parser, test_name)
            agent_status &= self.set_agent_status(
                agent_log_parser=agent_log_parser)

        logs += "\n{line}\n{part_line} End Of Docker Logs {part_line}\n{line}\n\n".format(line='=' * 150,
                                                                                          part_line='=' * 65)
        return agent_status, logs, summary

    def remove_test_container(self, container, remove_volume: bool = True):
        self.remove_container(container, remove_volume)
        self.containers.remove(container)

    @staticmethod
    def remove_container(container, remove_volume: bool = True):
        try:
            container.stop()
            container.remove(v=remove_volume)
        except Exception as e:
            Logger.logger.error(
                "Error while stopping and removing container: {}".format(e))

    def set_agent_status(self, agent_log_parser):
        if not TestUtil.get_arg_from_dict(self.test_driver.kwargs, "ignore_agent_errors"):
            if agent_log_parser.errors or not agent_log_parser.has_agent:
                return statics.FAILURE
        return statics.SUCCESS

    @staticmethod
    def set_agent_summery(agent_log_parser, test_name):
        summary = "{sep} {image} {sep}\n".format(sep='-' * 5, image=test_name)
        for message in sorted(agent_log_parser.errors, key=container_logs_handler.AgentLog.get_pid):
            summary += "{}'\n'".format(message)
        return summary

    def parse_test_logs(self, container, agent_log_parser, test_name):
        logs = ""
        try:
            logs += "\n\n{d} {test} {d}\n\n".format(
                d='-' * 70, test=container.name)
            logs += 'docker container inspect:\n{}\n\n'.format(
                json.dumps(self.docker.inspect(container=container)))
            logs += 'All container logs:\n'
            logs += container.logs(stderr=True).decode() + "\n"
            logs += "{sep} Agent Summery {sep}".format(sep='-' * 67)
            logs += '\nSummary of agent logs (errors and warnings printed by agent)\nTest: {}:\n'.format(
                test_name)
            has_agent = agent_log_parser.has_agent
            if not TestUtil.get_arg_from_dict(self.test_driver.kwargs, "ignore_agent_errors"):
                logs += ("[SUCCESS] Agent loaded successfully!!\n" if has_agent else "[ERROR] Agent was not loaded!!\n")

            for message in sorted(agent_log_parser.all, key=container_logs_handler.AgentLog.get_pid):
                logs += str(message) + '\n'
        except Exception as e:
            Logger.logger.error("Error while reading logs: {}".format(e))
        return logs

    @staticmethod
    def test_summery(ap, test_name):
        summary = "{sep} {image} {sep}\n".format(sep='-' * 5, image=test_name)
        for message in sorted(ap.errors, key=container_logs_handler.AgentLog.get_pid):
            summary += "{}'\n'".format(message)
        return summary

    def encrypt_secret(self, input_full_path: str, output_full_path: str):
        """
        loop directory and encrypt
        return {"file name": "key-id"}
        """
        subsecrets = {}
        for i in os.listdir(input_full_path):
            if os.path.isfile(os.path.join(input_full_path, i)):
                subsecrets[os.path.basename(i)] = super(BaseDockerizeTest, self).encrypt_secret(
                    input_full_path=os.path.join(input_full_path, i),
                    output_full_path=os.path.join(output_full_path, i))

        return subsecrets

    def start_workloads_statistics(self, containers: dict, state: str):
        """
        :param containers: {"workload name": ["container name"]}
        :return:
        """
        container_statistics = dict()

        for workload_name in containers.keys():
            container_statistics[workload_name] = dict(CPU=None, MEMORY=None)

        thread_signal = ThreadSignal()
        thread = Thread(target=self.get_containers_memory_and_cpu,
                        args=(containers, state, thread_signal))
        thread.start()

        return thread, thread_signal

    def end_workloads_statistics(self, thread, thread_signal: ThreadSignal):
        thread_signal.terminate()
        thread.join()

    def get_containers_memory_and_cpu(self, containers_names: list, state: str, thread_signal: ThreadSignal):
        tmp_statistics = dict()

        for workload_name in containers_names:
            tmp_statistics[workload_name] = dict(CPU=[], MEMORY=[])
        while not thread_signal.if_terminate():
            try:
                if self.docker.docker_client is None:
                    continue
                for container_name in containers_names:
                    stats = self.docker.get_container_stats(container_name)
                    cpu = self.docker.calculate_container_cpu_percentage(
                        docker_stats=stats)
                    _, _, memory = self.docker.get_container_memory_statistics(
                        docker_stats=stats)
                    tmp_statistics[container_name][CPU].append(round(cpu, 2))
                    tmp_statistics[container_name][MEMORY].append(
                        round(memory, 2))
            except Exception as e:
                Logger.logger.error(f'error: {e}')
            finally:
                time.sleep(1)

        for k, v in tmp_statistics.items():
            if k not in self.container_statistics:
                self.container_statistics[k] = dict()
            if state not in self.container_statistics[k]:
                self.container_statistics[k][state] = dict(CPU=0, MEMORY=0)

            self.container_statistics[k][state][CPU] = average(v[CPU])
            self.container_statistics[k][state][MEMORY] = average(v[MEMORY])

    def test_cpu_usage(self, wlids):

        if isinstance(wlids, str):
            wlids = [wlids]
        for wlid in wlids:
            name = Wlid.get_name(wlid)
            if name not in self.container_statistics or Statistics.clear_state not in self.container_statistics[name]:
                continue
            clr_cpu = self.container_statistics[name][Statistics.clear_state]["CPU"]
            if clr_cpu == 0:
                continue

            if Statistics.attached_state in self.container_statistics[name]:
                att_cpu = self.container_statistics[name][Statistics.attached_state]["CPU"]
                assert clr_cpu * \
                       2 > att_cpu, f"High cpu usage after attach, container_statistics: {self.container_statistics}"

            if Statistics.signed_state in self.container_statistics[name]:
                att_cpu = self.container_statistics[name][Statistics.signed_state]["CPU"]
                assert clr_cpu * \
                       2 > att_cpu, f"High cpu usage after sign, container_statistics: {self.container_statistics}"
            if Statistics.testing_state in self.container_statistics[name]:
                att_cpu = self.container_statistics[name][Statistics.testing_state]["CPU"]
                assert clr_cpu * \
                       2 > att_cpu, f"High cpu usage, container_statistics: {self.container_statistics}"


def average(lst: list):
    return sum(lst) / len(lst) if len(lst) > 0 else "empty list"
