import collections
import io
import json
import logging
import os
import random
import shutil
import string
import subprocess
import sys
import time
import traceback
from builtins import staticmethod
from datetime import datetime

import requests
import yaml

from systest_utils.tests_logger import Logger
from systest_utils.wlid import Wlid


def read_from_book():
    try:
        with open('text_book.txt', 'r') as f:
            return f.read()
    except:
        Logger.logger.debug('Cant read text from book')
        return None


class TestUtil(object):
    """docstring for helpful"""
    text_book = read_from_book()

    def __init__(self):
        super(TestUtil, self).__init__()

    @staticmethod
    def run_and_ignore_errors(target, **kwargs):
        """
        run a function and ignore all exceptions

        :param target: function to run
        :param kwargs: args function is expecting to receive
        """
        try:
            target(**kwargs)
        except:
            pass

    @staticmethod
    def set_stream_capture(logger_err_handler, logger_out_handler):
        try:
            Logger.remove_stream(logger_err_handler)
            Logger.remove_stream(logger_out_handler)
        except:
            pass
        stdout = OutputCapturer()
        stderr = OutputCapturer()
        stdout.init_buf(real_std=sys.stdout)
        stderr.init_buf(real_std=sys.stderr)
        sys.stdout = stdout
        sys.stderr = stderr

        logger_err_handler = Logger.add_stream(
            stream=sys.stderr, level=logging.ERROR)
        logger_out_handler = Logger.add_stream(
            stream=sys.stdout, level=logging.DEBUG)

        return logger_err_handler, logger_out_handler

    @staticmethod
    def unset_stream_capture(stderr, stdout):
        sys.stdout = sys.stdout.real_std
        sys.stderr = sys.stderr.real_std

        Logger.remove_stream(stderr)
        Logger.remove_stream(stdout)

        logger_err_handler = Logger.add_stream(stream=sys.stderr, level=logging.ERROR)
        logger_out_handler = Logger.add_stream(stream=sys.stdout, level=logging.DEBUG)

        return logger_err_handler, logger_out_handler

    @staticmethod
    def get_full_exception_debug(exc_info):
        if not exc_info:
            return ''
        if isinstance(exc_info, collections.Iterable) and len(exc_info) == 3:
            exc_type, exc_obj, exc_tb = exc_info
            out = ''.join(traceback.format_tb(exc_tb))
            return out + "\n{0}: {1}\n".format(exc_type.__name__, exc_obj)
        return str(exc_info)

    @staticmethod
    def create_dir(dir_name: str, override: bool = True):
        if override and os.path.exists(dir_name):
            shutil.rmtree(dir_name)
        os.makedirs(dir_name, exist_ok=True)
        Logger.logger.debug("{} dir created".format(dir_name))

    @staticmethod
    def clone_git_repository(repo_url, destination_path):
        """
        Clone git repository locally

        :param repo_url: Repository you want to clone.
        :param destination_path: Destination path to store repository.
        :return: True if the repository is downloaded properly, False otherwise.
        """ 
        try:
            # Run the git clone command
            subprocess.check_output(['git', 'clone', repo_url, destination_path], stderr=subprocess.STDOUT, universal_newlines=True)
            return True
        except subprocess.CalledProcessError as e:
            # If the command fails, print the error message and return False
            print(f"Failed to clone repository: {e.output}")
            return False

    @staticmethod
    def random_string(length=16):
        if TestUtil.text_book and len(TestUtil.text_book) - length >= 0:
            start_location = random.randint(0, len(TestUtil.text_book) - length)
            return ' '.join(e for e in TestUtil.text_book[start_location: start_location + length] if e.isalnum())
        return ''.join(random.choices(population=string.ascii_letters + string.digits, k=length))

    @staticmethod
    def check_duration(func, args, times_to_repeat):

        # Check time of loop operations
        i = 0
        start = time.time()
        while i < times_to_repeat:
            i += 1
        end = time.time()
        i_dur = end - start

        # Start test
        i = 0
        start = time.time()
        while i < times_to_repeat:
            func(**args)
            i += 1
        end = time.time()
        return end - start - i_dur

    @staticmethod
    def get_class_members(obj):
        """
        :param obj: class object
        :return: dict of all local members and there values
        """
        return {i[0]: i[1] for i in list(filter(lambda x: not x[0].startswith('__'), obj.__dict__.items()))}

    @staticmethod
    def get_time(start: float, end: float = time.time()):
        # display time in format minute:second.millisecond
        return '{0:02.0f}:{1:02.03f}'.format(*divmod(end - start, 60))

    @staticmethod
    def is_abs_path(file_path: str):
        if not isinstance(file_path, str):
            raise Exception("in is_abs_path. wrong type, expecting str received {}".format(type(file_path)))
        if not os.path.isabs(file_path):
            raise Exception("file path {} is not absolute path".format(file_path))
        return file_path

    @staticmethod
    def is_abs_paths(files_paths):
        if isinstance(files_paths, str):
            return TestUtil.is_abs_path(files_paths)
        if isinstance(files_paths, list):
            return [TestUtil.is_abs_path(i) for i in files_paths]
        raise Exception("in is_abs_paths. wrong type")

    @staticmethod
    def get_files_in_dir(file_path: str, file_type: str = "yaml"):
        return [os.path.join(file_path, f) for f in os.listdir(file_path) if
                os.path.isfile(os.path.join(file_path, f)) and f.endswith(".{}".format(file_type))]

    @staticmethod
    def get_some_files_in_dir(file_path: str, file_type: str = "yaml", include: str = None, exclude: str = None):
        files = TestUtil.get_files_in_dir(file_path=file_path, file_type=file_type)
        if include:
            include = include if isinstance(include, list) else [include]
            files = [i for i in files for j in include if j in os.path.basename(i)]
        if exclude:
            exclude = exclude if isinstance(exclude, list) else [exclude]
            files = [i for i in files for j in exclude if j not in os.path.basename(i)]
        return list(filter(None, files))

    @staticmethod
    def get_abs_path(relative_path: str = "", file_name: str = None):
        if not file_name:
            return None
        if os.path.isfile(file_name):
            return file_name
        file = os.path.abspath(os.path.join(relative_path, file_name))
        if not os.path.isfile(file):
            raise Exception("cant find file {}".format(file))
        return file

    @staticmethod
    def get_abs_paths(full_path: str, files: list = None):
        if not files:
            return None
        return [TestUtil.get_abs_path(full_path, i) for i in files]

    @staticmethod
    def sleep(t: int, m: str = None, level: str = "debug"):
        if t == 0:
            return
        Logger.get_logger_by_level(level)("{}sleeping for {} seconds".format("{}. ".format(m) if m else "", t))
        time.sleep(t)

    @staticmethod
    def generate_random_name(*name):
        return 'systest-{}-{}-{}'.format("-".join(name), datetime.now().strftime("%d-%m-%Y.%H-%M-%S"),
                                         random.randint(0, 1000))

    @staticmethod
    def generate_k8s_random_name(*name):
        return 'systest-{}-{}'.format("-".join(name), TestUtil.random_string(length=4)).lower()

    @staticmethod
    def ping(host: str, times=3, wait=10):
        assert isinstance(host, str) or host != "", "expecting ip received: {}".format(host)

        for i in range(times):
            if TestUtil.run_command("ping -c 1 {}".format(host).split(" "))[0] == 0:
                return True
            TestUtil.sleep(wait)
        return False

    @staticmethod
    def run_command(command_args: list, timeout=60, display_stdout: bool = True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd: str=""):
        if isinstance(command_args, str):
            command_args = command_args.split(" ")
        start = time.time()
        try:
            return_obj = subprocess.run(command_args, timeout=timeout, stdout=stdout, stderr=stderr, cwd=cwd) if cwd \
                else subprocess.run(command_args, timeout=timeout, stdout=stdout, stderr=stderr)
        except Exception as e:
            Logger.logger.error(e)
            raise Exception(e)
        end = time.time()

        if return_obj.returncode:
            Logger.logger.error(
                "Command - {0} - Has Failed, time: {1}".format(" ".join(command_args), TestUtil.get_time(start, end)))
            Logger.logger.error("Has Failed with Error {0}".format(return_obj.returncode))
            Logger.logger.error("StdOut: {0}".format(return_obj.stdout))
        elif display_stdout:
            Logger.logger.info("{0}".format(" ".join(command_args)))
            Logger.logger.info(
                "Return Code: {0}, time: {1}".format(return_obj.returncode, TestUtil.get_time(start, end)))
            Logger.logger.debug("StdOut: {0}".format(return_obj.stdout))

        return return_obj.returncode, return_obj

    @staticmethod
    def constant_get_request(duration: int = 0, **kwargs):
        """
        run get requests for a fixed duration
        :param duration:
        :param kwargs:
        :return: return false if failed to connect after X retries
        """
        start = time.time()
        while True:
            if not TestUtil.simple_get_request(**kwargs):
                return False
            if time.time() - start > duration:
                break

        return True

    @staticmethod
    def simple_get_request(url: str, retries=3, wait=10, port: int = None, verify: bool = True):
        """
        :return: return false if failed to connect after X retries
        """
        if url.find("://") < 0:
            url = "http://" + url
        if port:
            url += f":{port}/"
        i = 0
        while True:
            try:
                stat = requests.get(url, verify=verify, timeout=5).status_code
                if 300 > stat >= 200:
                    return True
            except Exception as err:
                Logger.logger.warning(f'requests.get({url}), exception info {err}')
            if i < retries:
                TestUtil.sleep(wait)
                i += 1
            else:
                break
        return False

    @staticmethod
    def get_arg_from_dict(dic: dict, arg, default=None):
        return dic[arg] if arg in dic and dic[arg] is not None else default

    @staticmethod
    def load_yaml_file(path: str, file: str):
        if isinstance(file, str):
            _file = TestUtil.get_abs_path(relative_path=path, file_name=file)
            with open(_file, 'r') as f:
                file_yaml = f.read()
            return TestUtil.yaml_file_to_dict(file_yaml=file_yaml)
        return file

    @staticmethod
    def yaml_file_to_dict(file_yaml):
        try:
            file_dict = yaml.safe_load(file_yaml)
        except Exception as e:
            try:
                file_dict = yaml.safe_load_all(file_yaml)
            except Exception as e:
                Logger.logger.error(
                    'Fail to process Test Configuration File: {0} Exception info {1}'.format(file_yaml, e))
                raise Exception("Fail to Process Configuration File".format(file_yaml))

        return file_dict

    @staticmethod
    def json_file_to_dict(path: str, file: str):
        _file = TestUtil.get_abs_path(relative_path=path, file_name=file)
        try:
            with open(_file, 'r') as f:
                file_json = f.read()
                file_dict = json.loads(file_json)
        except Exception as e:
            Logger.logger.error('Fail to process Test Configuration File: {0} Exception info {1}'.format(file, e))
            raise Exception("Fail to Process Configuration File".format(file))
        return file_dict

    @staticmethod
    def get_wlid(cluster_name=str(), namespace=str(), application_kind=str(), application_name=str()):
        ca_app_wlid = Wlid(cluster=cluster_name, namespace=namespace, workload_kind=application_kind,
                           workload=application_name)

        return ca_app_wlid.__str__().lower()

    @staticmethod
    def get_wlid_from_workload_name(wlids: list, workload_name: str):
        for i in wlids:
            if Wlid.get_name(i) == workload_name:
                return i
        return None

    @staticmethod
    def get_class_methods(class_name):
        return [func for func in dir(class_name) if callable(getattr(class_name, func)) and not func.startswith("_")]


class OutputCapturer(io.StringIO):
    """all prints into a file writer"""

    def init_buf(self, real_std=None):
        if real_std:
            self.real_std = real_std
        self.output_buf = ''

    def write(self, content):
        self.real_std.write(content)
        self.output_buf += content


class IteratorSetup(object):
    def __iter__(self):
        self._index = 0
        return self

    def __next__(self):
        if self._index == 0:
            self._index += 1
            return self
        self._index = 0
        raise StopIteration

    def __sizeof__(self):
        return 1

    def __len__(self):
        return 1
