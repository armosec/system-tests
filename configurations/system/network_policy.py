from systest_utils import TestUtil


class NetworkPolicy(object):
    def __init__(self, name: str,
                 np: dict = None,
                 client_wlids: list = [],
                 server_ports: list = [],
                 target_ports: list = [],
                 server_wlids: list = [],
                 service_ip: list = [],
                 service_port_ranges: list = [],
                 server_attributes: dict = {},
                 client_attributes: dict = {},
                 guid='',
                 port_ranges: list = [],
                 ip_ranges: list = [],
                 enforcementAction='block',
                 permissions='allow',
                 policy_type='explicit',
                 permissive_mode=False):

        super().__init__()
        self.name = TestUtil.generate_random_name(name)
        self.np: dict = np

        if not isinstance(server_wlids, list):
            server_wlids = [server_wlids]
        self.server_wlid = server_wlids

        if not isinstance(service_ip, list):
            service_ip = [service_ip]
        self.k8s_service = service_ip

        if not isinstance(port_ranges, list):
            port_ranges = [port_ranges]
        self.port_ranges = port_ranges

        if not isinstance(ip_ranges, list):
            ip_ranges = [ip_ranges]
        self.ip_ranges = ip_ranges

        if not isinstance(client_wlids, list):
            client_wlids = [client_wlids]
        self.client_wlid = client_wlids

        if not isinstance(server_ports, list):
            server_ports = [server_ports]
        self.server_port = server_ports

        if not isinstance(target_ports, list):
            target_ports = [target_ports]
        self.k8s_service_port = target_ports

        if not isinstance(service_port_ranges, list):
            service_port_ranges = [service_port_ranges]
        self.service_port_ranges = service_port_ranges

        self.client_attributes = client_attributes
        self.server_attributes = server_attributes

        self.guid = guid

        self.enforcement_action = enforcementAction
        self.permissions = permissions
        self.policy_type = policy_type
        self.permissive_mode = permissive_mode

    def update_np(self):
        """
        update np member with rest of class members
        :return:
        """
        if not self.np:
            self.np = self._np()

        self.np["name"] = self.name

        self.np['enforcementAction'] = self.enforcement_action
        if self.guid:
            self.np['guid'] = self.guid
        if self.permissions:
            self.np['permissions'] = self.permissions
        if self.policy_type:
            self.np['policyType'] = self.policy_type
        if self.permissive_mode:
            self.np['permissiveMode'] = self.permissive_mode

        if len(self.server_attributes) > 0:
            if not self.np['serverList']:
                self.np['serverList'] = list()
            if len(self.np['serverList']) == 0:
                self.np['serverList'].append(self._server())
            self.np['serverList'][0]["designatorType"] = "attribute"
            self.np['serverList'][0]['attributes'] = self.server_attributes
        else:
            for i, _ in enumerate(self.server_wlid):
                if len(self.np['serverList']) == i:
                    if not self.np['serverList']:
                        self.np['serverList'] = list()
                    self.np['serverList'].append(self._server())
                if not self.np['serverList']:
                    self.np['serverList'] = list()
                self.np['serverList'][i]["wlid"] = self.server_wlid[i]
                self.np['serverList'][i]["designatorType"] = "wlid"

        if len(self.client_attributes) > 0:
            if not self.np['clientList']:
                self.np['clientList'] = list()
            if len(self.np['clientList']) == 0:
                self.np['clientList'].append(self._client())
            self.np['clientList'][0]["designatorType"] = "attribute"
            self.np['clientList'][0]['attributes'] = self.client_attributes
        else:
            for i, _ in enumerate(self.client_wlid):
                if len(self.np['clientList']) == i:
                    self.np['clientList'].append(self._client())
                self.np['clientList'][i]["wlid"] = self.client_wlid[i]
                self.np['clientList'][i]["designatorType"] = "wlid"

        for i, _ in enumerate(self.np["serverList"]):
            if len(self.k8s_service) != 0:
                self.np['serverList'][i]['k8sServiceIP'] = self.k8s_service[0]
            if len(self.server_port) != 0:
                # todo
                self.np['serverList'][i]['ports'].extend(self.server_port)
            if len(self.k8s_service_port) != 0:
                self.np['serverList'][i]['k8sServicePorts'].extend(self.k8s_service_port)
            if len(self.port_ranges) != 0:
                self.np['serverList'][i]['portRanges'].extend(self.port_ranges)
            if len(self.ip_ranges) != 0:
                self.np['serverList'][i]['ipRanges'].extend(self.ip_ranges)
            if len(self.service_port_ranges) != 0:
                self.np['serverList'][i]['servicePortRanges'].extend(self.service_port_ranges)

    @staticmethod
    def _np():
        return dict(
            guid="",
            name="",
            attributes=dict(),
            policyType="",
            permissions="",
            enforcementAction="",
            creation_time="",
            permissiveMode=False,
            serverList=[
                NetworkPolicy._server()
            ],
            clientList=[
                NetworkPolicy._client()
            ]
        )

    @staticmethod
    def _server():
        return dict(
            designatorType="",
            wlid="",
            wildwlid="",
            groupName="",
            ports=list(),
            attributes=dict(),
            k8sServiceName="",
            k8sServiceIP="",
            k8sServicePorts=list(),
            ipRanges=list(),
            portRanges=list(),
            servicePortRanges=list()
        )

    @staticmethod
    def _client():
        return dict(
            designatorType="",
            wlid="",
            wildwlid="",
            attributes=dict()
        )


class Designators(object):
    def __init__(self, type: str = "", wlid: str = "", wildwlid: str = "", attributes: dict = {}):
        super().__init__()
        self.type = type
        self.wlid = wlid
        self.wildwlid = wildwlid
        self.attributes = attributes


class v3CustomeExtensions(object):
    def __init__(self, object_ID: str = "", values: list = None):
        super().__init__()

        self.object_ID = object_ID
        self.values = values if values is not None else []

    def update_v3_custome_extensions(self):
        if len(self.object_ID) == 0 and len(self.values) == 0:
            return {}
        return {
            "objectID": self.object_ID,
            "values": self.values
        }


class TLSCertificateProperties(object):
    def __init__(self, common_name: str = "",
                 SANs: list = None,
                 organization_name: str = "",
                 issuer_name: str = "",
                 issuer_certificate_ID: str = "",
                 v3_custome_extensions: dict = None,
                 ):
        super().__init__()

        self.common_name = common_name
        self.SANs = SANs if SANs is not None else []
        self.organization_name = organization_name
        self.issuer_name = issuer_name
        self.issuer_certificate_ID = issuer_certificate_ID
        self.v3_custome_extensions = v3_custome_extensions if v3_custome_extensions is not None else v3CustomeExtensions()

    def update_tls_certificate_properties(self):
        return {
            "commonName": self.common_name,
            "SANs": self.SANs,
            "organizationName": self.organization_name,
            "issuerCN": self.issuer_name,
            "issuerCertificateID": self.issuer_certificate_ID,
            "v3CustomeExtensions": self.v3_custome_extensions.update_v3_custome_extensions()
        }


class NetworkPolicyIngress(object):
    def __init__(self,
                 np: dict = None,
                 name: str = "",
                 policy_type: str = "ingress",
                 permissions: str = "",
                 guid: str = "",
                 creation_time: str = "",
                 wlids: list = None,
                 wildwlids: list = None,
                 attributes: dict = None,
                 ip_ranges: list = None,
                 port_ranges: list = None,
                 ports: list = None,
                 hosts: list = None,
                 is_certificate_mandatory: bool = False,
                 tls_certificate_properties: dict = None
                 ):

        super().__init__()

        self.np = np
        self.guid = guid
        self.policy_type = policy_type
        self.name = TestUtil.generate_random_name(name)
        self.permissions = permissions
        self.creation_time = creation_time
        self.attributes = attributes

        self.designators = []
        if wlids is None:
            wlids = []
        for wlid in wlids:
            self.designators.append(Designators("wlid", wlid, "", {}))
        if wildwlids is None:
            wildwlids = []
        for wildwlid in wildwlids:
            self.designators.append(Designators("wildwlid", "", wildwlid, {}))
        if attributes is None:
            attributes = []
        for attribute in attributes:
            self.designators.append(Designators("attributes", "", "", attribute))

        self.ip_ranges = []
        if ip_ranges is None:
            ip_ranges = []
        for ip_range in ip_ranges:
            self.ip_ranges.append(ip_range)

        self.port_range = []
        if port_ranges is None:
            port_ranges = []
        for port_range in port_ranges:
            self.port_range.append(port_range)

        self.ports = []
        if ports is None:
            ports = []
        for port in ports:
            self.ports.append(port)

        self.hosts = []
        if hosts is None:
            hosts = []
        for host in hosts:
            self.hosts.append(host)

        self.is_certificate_mandatory = is_certificate_mandatory
        self.tls_certificate_properties = tls_certificate_properties if tls_certificate_properties is not None else TLSCertificateProperties()

    def add_wlid(self, wlid):
        self.designators.append(Designators("wlid", wlid, "", {}))

    def add_host(self, host):
        self.hosts.append(host)

    def update_np(self):
        """
        update np member with rest of class members
        :return:
        """
        if not self.np:
            self.np = self._inp(self)
        if self.guid:
            self.np['guid'] = self.guid
        self.np['name'] = self.name
        if self.policy_type:
            self.np['policyType'] = self.policy_type
        if self.permissions:
            self.np['permissions'] = self.permissions
        if self.creation_time:
            self.np['creation_time'] = self.creation_time
        for i, d in enumerate(self.designators):
            self.np["designators"][i]["designatorType"] = d.type
            self.np["designators"][i]["wlid"] = d.wlid
            self.np["designators"][i]["wildwlid"] = d.wildwlid
            self.np["designators"][i]["attributes"] = d.attributes
        self.np["peers"][0]["ipRanges"] = self.ip_ranges
        self.np["peers"][0]["ports"] = self.ports
        self.np["peers"][0]["portRanges"] = self.port_range
        self.np["peers"][0]["hosts"] = self.hosts
        self.np["peers"][0]["isCertificateMandatory"] = self.is_certificate_mandatory
        self.np["peers"][0][
            "tlsCertificateProperties"] = self.tls_certificate_properties.update_tls_certificate_properties()

    @staticmethod
    def _inp(self):
        return dict(
            guid="",
            name="",
            permissions="",
            creation_time="",
            designators=[
                self._designator()
            ],
            peers=[
                self._peer(self)
            ]
        )

    @staticmethod
    def _designator():
        return dict(
            designatorType="",
            wlid="",
            wildwlid="",
            attributes=dict()
        )

    @staticmethod
    def _peer(self):
        return dict(
            hosts=list(),
            ports=list(),
            ipRanges=list(),
            portRanges=list(),
            isCertificateMandatory=False,
            tlsCertificateProperties=self._tls_certificate_properties()
        )

    @staticmethod
    def _tls_certificate_properties():
        return dict(
            common_name="",
            SANs=[],
            organizationName="",
            issuerCN="",
            issuerCertificateID="",
            v3CustomeExtensions={}
        )
