#!/usr/bin/env python
import argparse
import base64
import os
import sys
from datetime import datetime
from logging import DEBUG, ERROR
from random import seed

import requests
import socket

from configurations import BACKENDS, CREDENTIALS, ALL_TESTS
from systest_utils import Logger, TestUtil
from test_driver import TestDriver



def input_parser():
    # get arguments
    parser = argparse.ArgumentParser("CyberArmor system tests")

    parser.add_argument("--list", action="store", choices=["all", "b", "c", "t"], required=False,
                        help="print a list of available tests, customers and supported backends")

    parser.add_argument("-t", "--test-name", default="", action="store", required=False, dest="test_name",
                        help="test to run (all is the default.")
    parser.add_argument("-b", "--backend", default="", help="backend to run on.", action="store",
                        dest="backend")
    parser.add_argument("-c", "--customer", default="CyberArmorTests", help="Customer name", dest="customer")
    parser.add_argument("--logger", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="logger level", default="DEBUG",
                        dest="logger_level")

    parser.add_argument("--delete_test_tenant", choices=["ALWAYS", "TEST_PASSED", "NEVER"], help="when to delete test tenant", default="ALWAYS",
                        dest="delete_test_tenant")
    
    parser.add_argument("-f", "--fresh", action="store_true", dest="fresh", default=False,
                        help="refresh local docker images, build new ones (and remove the old ones).")

    parser.add_argument("--k8s_cluster", dest="cluster", default="minikube", help="cluster to run tests",
                        required=False)

    parser.add_argument("-agent", "--override-agent", action="store", default=None, dest='agent',
                        help="Use local agent. for example: -agent /local/agent/location/libcaa.so", required=False)

    parser.add_argument("-d", "--duration", action="store", dest='duration', help="test duration", type=int,
                        required=False)  # do not set default duration

    parser.add_argument("--skip_signing", action="store_true", default=False, dest='skip_signing',
                        help="skip signing images/files", required=False)
    parser.add_argument("--ignore_agent_errors", action="store_true", default=False, dest='ignore_agent_errors',
                        help="test will ignore agent error report. recommended when the skip_signing flag is on")
    parser.add_argument("--run_without_agent", action="store_true", default=False, dest='load_without_agent',
                        help="run workload without agent attached")
    parser.add_argument("--leave_redis_data", action="store_true", default=False, dest='leave_redis_data',
                        help="do not cleanup wlids from backend after test")

    parser.add_argument("--force-remove-container", action="store_true", default=False, dest="force_remove_container",
                        required=False, help="if container with same name is running then remove the running container")
    parser.add_argument("-lcn", "--leave-cyberarmor-namespace", action="store_true", default=False,
                        required=False, dest="leave_cyberarmor_namespace",
                        help="leave cyberarmor namespace after running a k8s test, default if false")
    parser.add_argument("-temp", "--temp-dir", action="store", default=os.path.abspath("temp"),
                        help="temp dir location. default: ./temp", required=False)
    parser.add_argument("--create-first-time-results", action="store_true", default=False,
                        help="will create first time results", required=False, dest="create_first_time_results")
    parser.add_argument("--kwargs", action="store", required=False, nargs='*', dest='kwargs',
                        help="adding additional values. example: --kwargs k0=v0 k1=v1;v11")
    

    return parser.parse_args()


def print_configurations(print_list: str = "all"):
    import json
    p = {}
    if print_list == "all" or print_list == "t":
        p["Tests"] = list(ALL_TESTS)
    if print_list == "all" or print_list == "c":
        p["Customers"] = list(CREDENTIALS.customer)
    if print_list == "all" or print_list == "b":
        p["Backends"] = list(BACKENDS.keys())
    print(json.dumps(p, indent=4))


def setup_logger(level=DEBUG, name: str = ""):
    # set logger
    Logger.set_logger(logging_level=level, name=name)

    # set output stream to logger
    logger_err_handler = Logger.add_stream(stream=sys.stderr, level=ERROR)
    logger_out_handler = Logger.add_stream(stream=sys.stdout, level=level)
    std_handlers = TestUtil.set_stream_capture(logger_err_handler, logger_out_handler)

    Logger.logger.debug('Logger file location: {}'.format(Logger.get_file_location()))


def main():

    # parse input
    args = input_parser()
    setup_logger(level=args.logger_level, name=args.test_name)

    # seed
    rand_seed = str(datetime.now())
    Logger.logger.info("Random seed is: {}".format(rand_seed))
    seed(rand_seed)

    if args.list:
        print_configurations(args.list)
        exit(0)

    if args.test_name not in ALL_TESTS or args.customer != CREDENTIALS.customer:
        print_configurations()
        exit(1)

    # ignore https requests warnings
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    # set default timeout to 11 minutes
    socket.setdefaulttimeout(11*60)

    t = TestDriver(**vars(args))
    res = t.main()
    Logger.logger.debug('Logger file location: {}'.format(Logger.get_file_location()))
    exit(res)


if __name__ == "__main__":
    main()
