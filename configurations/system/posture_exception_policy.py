from systest_utils import TestUtil


class PostureExceptionPolicy(object):
    def __init__(self, name: str,
                 pe: dict = None,
                 guid='',
                 policy_type='postureExceptionPolicy',
                 creation_time: str = '',
                 actions: list = [],
                 resources_attributes: dict = None,
                 wlids: list = None,
                 wildwlids: list = None,
                 posture_policies_attributes: dict = {},
                 framework_name: str = '',
                 control_name: str = '',
                 rule_name: str = ''):

        super().__init__()
        self.name = TestUtil.generate_random_name(name)
        self.pe: dict = pe
        self.guid = guid
        self.policy_type = policy_type
        self.creation_time = creation_time

        if not isinstance(actions, list):
            actions = [actions]
        self.actions = actions

        self.resources = []
        if wlids is None:
            wlids = []
        for wlid in wlids:
            self.resources.append(Designators("wlid", wlid, "", {}))
        if wildwlids is None:
            wildwlids = []
        for wildwlid in wildwlids:
            self.resources.append(Designators("wildwlid", "", wildwlid, {}))
        if resources_attributes is None:
            resources_attributes = {}
        self.resources.append(Designators("attributes", "", "", resources_attributes))

        self.posture_policies_attributes = posture_policies_attributes
        self.framework_name = framework_name
        self.control_name = control_name
        self.rule_name = rule_name

    def update_pe(self):
        """
        update pe member with rest of class members
        :return:
        """
        if not self.pe:
            self.pe = self._pe()
        self.pe["name"] = self.name
        if self.guid:
            self.pe['guid'] = self.guid
        if self.policy_type:
            self.pe['policyType'] = self.policy_type
        if self.creation_time:
            self.pe['creation_time'] = self.creation_time
        self.pe['actions'] = self.actions
        for i, d in enumerate(self.resources):
            self.pe["resources"][i]["designatorType"] = d.designatorType
            self.pe["resources"][i]["wlid"] = d.wlid
            self.pe["resources"][i]["wildwlid"] = d.wildwlid
            self.pe["resources"][i]["attributes"] = d.attributes
        self.pe['posturePolicies'][0]['framework_name'] = self.framework_name
        self.pe['posturePolicies'][0]['control_name'] = self.control_name
        self.pe['posturePolicies'][0]['rule_name'] = self.rule_name
        self.pe['posturePolicies'][0]['attributes'] = self.posture_policies_attributes

    @staticmethod
    def _pe():
        return dict(
            guid="",
            name="",
            attributes=dict(),
            policyType="",
            creation_time="",
            actions=list(),
            resources=[
                PostureExceptionPolicy._designator()
            ],
            posturePolicies=[
                PostureExceptionPolicy._posturepolicies()
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
    def _posturepolicies():
        return dict(
            framework_name="",
            control_name="",
            rule_name="",
            attributes=dict()
        )


class Designators(object):
    def __init__(self, designatorType: str = "", wlid: str = "", wildwlid: str = "", attributes: dict = {}):
        super().__init__()
        self.designatorType = designatorType
        self.wlid = wlid
        self.wildwlid = wildwlid
        self.attributes = attributes
