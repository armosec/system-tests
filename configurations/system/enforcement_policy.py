from systest_utils import TestUtil
from typing import List

# ENF_OBJECTS = 
AGENT_SIGNATURE = "Agent Signature"
NATIVE_MODULE_SIGNATURE = "Native Module Signature"
INTERPRETED_MODULE_SIGNATURE = "Interpreted Module Signature"
ENVIRONMENT_VARIABLES = "Environment Variables"
COMMAND_LINE_ARGUMENTS = "Command Line Arguments"
DEBUGGING_ATTACHMENT = "Debugging Attachment"
PRIVILEGE_CHANGED = "Privilege Changed"

# ENF_EXISTENCE
MANDATORY = "Mandatory"
ALLOWED = "Allowed"
FORBIDDEN = "Forbidden"

# ENF_EVENTS
MISMATCH = "Mismatch"
MISSING = "Missing"
UNSIGNED = "Unsigned"
UNRECOGNIZED = "Unrecognized"
UP = "Up"
DOWN = "Down"

# ENF_ACTIONS
ALERT = "Alert"
SECURITYFEATURES_OFF = "Securityfeatures Off"
NETWORKOFF = "Notwork Off"
KILL = "Kill"


class EnforcementRule:
    def __init__(self,
                 object: List[str],
                 existence: List[str],
                 event: List[str],
                 action: List[str]):
        self.object = object
        self.existence = existence
        self.event = event
        self.action = action

    def __dict__(self):
        return dict(
            object=self.object,
            existence=self.existence,
            event=self.event,
            action=self.action
        )


class EnforcementPolicy(object):
    def __init__(self, name: str,
                 en: dict = None,
                 rules: List[EnforcementRule] = []):

        super().__init__()
        self.name = TestUtil.generate_random_name(name)
        self.en: dict = en
        self.rules = rules

    def update_en(self):
        """
        update enforcement policy
        :return:
        """
        if not self.en:
            self.en = self._en()

        self.en["name"] = self.name

        if self.rules:
            if len(self.rules) > 0:
                if not self.en['enforcementList']:
                    self.en['enforcementList'] = list()
                for rule in self.rules:
                    self.en['enforcementList'].append(rule.__dict__())

    @staticmethod
    def _rule():
        return dict(
            object=list(),
            existence=list(),
            event=list(),
            action=list()
        )

    @staticmethod
    def _en():
        return dict(
            guid="",
            name="",
            attributes=dict(),
            policyType="",
            creation_time="",
            designators=dict(),
            enforcementList=list()
        )


class Designators(object):
    def __init__(self, type: str = "", wlid: str = "", wildwlid: str = "", attributes: dict = {}):
        super().__init__()
        self.type = type
        self.wlid = wlid
        self.wildwlid = wildwlid
        self.attributes = attributes
