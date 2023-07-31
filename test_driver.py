import os
import shutil
import sys
import time
import traceback

import junit_xml

from configurations.system import customers, tests, backends
from infrastructure.backend_api import ControlPanelAPI
from systest_utils import Logger, statics
from systest_utils import systests_utilities


class TestDriver(object):
    def __init__(self,
                 test_name: str,
                 backend: str,
                 customer: str,
                 temp_dir: str = "temp",
                 fresh: bool = True,
                 # duration: int = 3,
                 **kwargs):
        # set objects
        self.test_name = test_name
        self.credentials_obj: customers.Credentials = customers.CREDENTIALS
        self.backend_obj: backends.Backend = backends.BACKENDS[backend] if backend != '' else None

        # other test features
        self.agent_location = kwargs["agent"] if "agent" in kwargs else None
        self.temp_dir = os.path.abspath(temp_dir)
        self.refresh = fresh
        self.duration = systests_utilities.TestUtil.get_arg_from_dict(kwargs, "duration", 3) * 60

        self.kwargs = self.parse_kwargs(kwargs)

    def main(self):

        # ControlPanelAPI
        backend = None
        if self.backend_obj != None:
            backend = ControlPanelAPI(user_name=self.credentials_obj.get_name(),
                                    password=self.credentials_obj.get_password(),
                                    customer=self.credentials_obj.get_customer(),
                                    client_id=self.credentials_obj.get_client_id(),
                                    secret_key=self.credentials_obj.get_secret_key(),
                                    url=self.backend_obj.get_dashboard_url(),
                                    auth_url=self.backend_obj.get_auth_url(),
                                    login_method=self.backend_obj.get_login_method(),
                                    customer_guid=self.backend_obj.get_customer_guid())

        status = statics.FAILURE
        summary = ""
        err = ""

        try:
            systests_utilities.TestUtil.create_dir(self.temp_dir)
            systests_utilities.TestUtil.create_dir(statics.DEFAULT_XML_PATH, override=False)

            status, summary = self.run_test(backend=backend)
        except Exception as e:
            status = statics.FAILURE
            err = e
            Logger.logger.error(e)
            summary = e
        finally:
            self.clear()
            self.final_report(status=status, err=err, summary=summary)
        return not status

    def run_test(self, backend: ControlPanelAPI = None):
        test_obj = tests.get_test(self.test_name)
        test_class_obj = test_obj.test_obj(test_driver=self, backend=backend, test_obj=test_obj)
        start = time.time()
        try:
            status, summary = test_class_obj.start()
        except Exception as ex:
            status = statics.FAILURE
            test_class_obj.failed()
            _, _, tb = sys.exc_info()
            function_name = tb.tb_frame.f_code.co_name

            if function_name != "cleanup":
                try:
                    _, _ = test_class_obj.cleanup()
                except Exception as e:
                    Logger.logger.info("Failed to cleanup test")
                    Logger.logger.error("error: {}".format(traceback.print_exc()))
            else:
                Logger.logger.info("Failed to cleanup test")
            summary = ex
            Logger.logger.error("error: {}".format(traceback.print_exc()))
        finally:
            Logger.logger.info('time: {}'.format(systests_utilities.TestUtil.get_time(start, time.time())))
        return status, summary

    def clear(self):
        Logger.logger.info("test driver clearing")
        # remove temp directory
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            Logger.logger.error(e)

    # ======================== report ==================================
    def final_report(self, status, err, summary):
        test_case = junit_xml.TestCase(name=self.test_name,
                                       classname=self.test_name,
                                       stdout=sys.stdout.output_buf,
                                       stderr=sys.stderr.output_buf)
        if status == statics.SUCCESS:
            Logger.logger.success("test {} status: SUCCESS".format(self.test_name))
        else:
            Logger.logger.error("test {} status: FAILURE".format(self.test_name))
            Logger.logger.error(summary)
            test_case.add_error_info(message=err, output=summary)

        test_suite = junit_xml.TestSuite(name="system-test", test_cases=[test_case])

        xml_file = os.path.join(statics.DEFAULT_XML_PATH, "{}.xml".format(self.test_name))
        with open(xml_file, 'w') as result:
            result.write(junit_xml.TestSuite.to_xml_string([test_suite]))
        Logger.logger.debug("xml file saved {}".format(xml_file))

    @staticmethod
    def parse_kwargs(kwargs: dict):
        if not kwargs["kwargs"]:
            return kwargs
        for i in kwargs["kwargs"]:
            arg = i.split('=')
            val = arg[1].split(",") if len(arg) > 1 else arg
            kwargs[arg[0]] = val if len(val) > 1 else val[0]
        return kwargs
