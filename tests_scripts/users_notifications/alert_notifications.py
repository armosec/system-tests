import json
import os
from datetime import datetime

import requests

from infrastructure import KubectlWrapper
from systest_utils import Logger, statics, TestUtil
from ..helm.base_helm import BaseHelm

NOTIFICATIONS_SVC_DELAY = 6 * 60

TEST_NAMESPACE = "alerts"


def get_access_token():
    url = "https://login.microsoftonline.com/50a70646-52e3-4e46-911e-6ca1b46afba3/oauth2/v2.0/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    body = {
        'grant_type': 'client_credentials',
        'client_id': os.getenv("MS_TEAMS_CLIENT_ID"),
        'client_secret': os.getenv("MS_TEAMS_CLIENT_SECRET"),
        'scope': 'https://graph.microsoft.com/.default'
    }
    response = requests.post(url, headers=headers, data=body)
    return response.json().get('access_token')


def get_messages_from_teams_channel(before_test):
    endpoint = f'https://graph.microsoft.com/v1.0/teams/{os.getenv("TEAMS_ID")}/channels/{os.getenv("CHANNEL_ID")}' \
               f'/messages/delta?$filter=lastModifiedDateTime gt {before_test}'
    headers = {
        'Authorization': 'Bearer ' + get_access_token(),
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    response = requests.get(endpoint, headers=headers)
    return response.json().get('value', [])


def assert_test_message_sent(before_test):
    messages = get_messages_from_teams_channel(before_test)
    assert len(messages) == 1, "expected to be only one message"
    assert "Test Alert" in str(messages[0]), "expected message to be a Test Alert"


def assert_vulnerability_message_sent(messages, cluster):
    found = 0
    for message in messages:
        message_string = str(message)
        if "New Vulnerability found" in message_string and cluster in message_string and "httpd:2" in message_string:
            found += 1
    assert found > 0, "expected to have at least one vulnerability message"


def assert_new_admin_message_sent(messages, cluster):
    found = 0
    for message in messages:
        message_string = str(message)
        if "New cluster admin was added" in message_string and cluster in message_string:
            found += 1
    assert found == 1, "expected to have exactly one new cluster admin message"


def assert_misconfiguration_message_sent(messages, cluster):
    found = 0
    for message in messages:
        message_string = str(message)
        if "Your complaince score has decreased" in message_string and cluster in message_string:
            found += 1
    assert found == 1, "expected to have exactly one new misconfiguration message"


def assert_all_messages_sent(begin_time, cluster):
    TestUtil.sleep(NOTIFICATIONS_SVC_DELAY, "waiting for notifications")
    for i in range(5):
        try:
            messages = get_messages_from_teams_channel(begin_time)
            assert str(messages).count(cluster) > 2, "expected to have at least 3 messages"
            assert_vulnerability_message_sent(messages, cluster)
            assert_new_admin_message_sent(messages, cluster)
            assert_misconfiguration_message_sent(messages, cluster)
        except AssertionError:
            if i == 4:
                raise
            TestUtil.sleep(30, "waiting additional 30 seconds for messages to arrive")


class AlertNotifications(BaseHelm):

    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super(AlertNotifications, self).__init__(test_driver=test_driver, test_obj=test_obj, backend=backend,
                                                 kubernetes_obj=kubernetes_obj)
        self.fw_name = None
        self.cluster = None

    def start(self):
        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        # test Agenda:
        # 1. Create a new framework with controls that should pass and lead to high complaince score
        # 2. Create Armo alert channel for the cluster
        # 3. Send test message to the created alert channel
        # 4. Create deployment from yaml
        # 5. Install kubescape and run first scan -> should get high score
        # 6. Change the framework, so we will get low score and add new SA to cluster admin
        # 7. Trigger another scan - this time we except to get low score
        # 8. Validate messages sent for the compliance drift, new cluster admin and vulnerabilities found

        self.cluster, _ = self.setup(apply_services=False)
        KubectlWrapper.add_new_namespace(TEST_NAMESPACE)

        Logger.logger.info("Stage 1: Post custom framework")
        self.fw_name = "systest-fw-" + self.cluster
        _, fw = self.post_custom_framework(framework_file="system-test-framework-high-comp.json",
                                           cluster_name=self.cluster)

        Logger.logger.info("Stage 2: Create new alert channel")
        channel_guid = self.create_alert_channel(self.cluster)

        Logger.logger.info("Stage 3: Send Test Alert message")
        before_test_message = datetime.utcnow().isoformat() + "Z"
        self.backend.send_test_message(channel_guid)

        Logger.logger.info("Stage 4: Read Test Alert message")
        assert_test_message_sent(before_test_message)

        Logger.logger.info('Stage 5: Apply deployment')
        workload_objs: list = self.apply_directory(path=self.test_obj["deployments"], namespace=TEST_NAMESPACE)
        self.verify_all_pods_are_running(namespace=TEST_NAMESPACE, workload=workload_objs, timeout=240)

        Logger.logger.info('Stage 6: Install kubescape with helm-chart')
        self.install_kubescape()

        Logger.logger.info('Stage 7: Trigger first scan')
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])
        TestUtil.sleep(NOTIFICATIONS_SVC_DELAY, "waiting for first scan to be saved in notification service")

        Logger.logger.info('Stage 8: Update custom framework')
        self.put_custom_framework(framework_file="system-test-framework-low-comp.json",
                                  framework_guid=fw['guid'], cluster_name=self.cluster)

        Logger.logger.info('Stage 9: Add SA to cluster-admin')
        KubectlWrapper.add_new_service_account_to_cluster_admin(service_account="service-account", namespace=TEST_NAMESPACE)

        Logger.logger.info('Stage 10: Trigger second scan')
        self.backend.create_kubescape_job_request(cluster_name=self.cluster, framework_list=[self.fw_name])

        Logger.logger.info('Stage 11: Assert all messages sent')
        assert_all_messages_sent(before_test_message, self.cluster)
        return self.cleanup()

    def cleanup(self, **kwargs):
        self.wait_for_report(report_type=self.backend.delete_custom_framework, framework_name=self.fw_name)
        self.delete_all_alert_channels_for_cluster(self.cluster)
        return super().cleanup(**kwargs)

    def post_custom_framework(self, framework_file, cluster_name: str):
        framework_name, ks_custom_fw = self.create_ks_custom_fw(cluster_name=cluster_name,
                                                                framework_file=framework_file)
        report_fw, _ = self.wait_for_report(report_type=self.backend.post_custom_framework, fw_object=ks_custom_fw)
        return ks_custom_fw, report_fw

    def put_custom_framework(self, framework_file, framework_guid: str, cluster_name: str):
        framework_name, ks_custom_fw = self.create_ks_custom_fw(cluster_name=cluster_name,
                                                                framework_file=framework_file,
                                                                framework_guid=framework_guid)
        report_fw, _ = self.wait_for_report(report_type=self.backend.put_custom_framework, fw_object=ks_custom_fw)
        return ks_custom_fw, report_fw

    def create_alert_channel(self, cluster: str):
        data = self.get_alert_channel_payload(cluster)
        created_alert_channel_response = self.backend.create_alert_channel(data)
        assert created_alert_channel_response, "Expected alert channel"
        guid = created_alert_channel_response.json()["channel"]["guid"]
        assert guid, "Expected alert channel's guid"
        return guid

    def install_kubescape(self):
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart()
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)

    def get_alert_channel_payload(self, cluster_name: str):
        with open(self.test_obj["alert_channel_file"], 'r') as file:
            data = json.load(file)
        data["channel"]["name"] = cluster_name + "_cluster"
        data["channel"]["context"]["webhook"]["id"] = os.getenv("CHANNEL_WEBHOOK")
        data["scope"][0]["cluster"] = cluster_name
        return data
