from systest_utils import TestUtil

'''
{
    "name": "simple-sec-policy-3",
    "policyType": "secretAccessList",
    "secrets": [
        {
            "sid": "sid://cluster-david-v1/namespace-default/secret-encrypted-credentials",
            "keyIDs": [
                {
                    "subSecretName": "password",
                    "keyID": "e3fbe2eba890e6b796bab1d1016dd0c0"
                }
            ]
        }
    ],
    "designators": [
        {
            "wlid": "wlid://cluster-david-v1/namespace-default/deployment-demo-service-secret"
        }
    ]
}

'''


class SecretPolicy(object):
    def __init__(self, name: str,
                 secp: dict = None,
                 guid: str = None,
                 secret_name: str = None,
                 key_id: str = None,
                 sub_secret_name: str = None,
                 designators: list = [],
                 policy_type: str = None,
                 secrets: list = [],
                 is_k8s: bool = True):

        super().__init__()
        self.name = TestUtil.generate_random_name(name)
        self.secp: dict = secp

        if not policy_type:
            policy_type = "secretAccessList"
        self.policyType = policy_type

        if not isinstance(designators, list):
            designators = [designators]
        self.designators = designators

        if not guid:
            self.guid = guid

        self.secrets = []
        if secrets:
            if not isinstance(secrets, list):
                secrets = [secrets]
            self.secrets = secrets

        if len(self.secrets) == 0:
            if is_k8s:
                sid = "sid://cluster-{cluster}/namespace-{namespace}/secret-%s" % secret_name
            else:
                sid = "sid://datacenter-{datacenter}/project-{project}/secret-%s" % secret_name
            if sub_secret_name:
                sid += "/subsecret-" + sub_secret_name
            key_ids = []
            if key_id:
                key_ids = {"keyID": key_id}
                if sub_secret_name:
                    key_ids["subSecretName"] = sub_secret_name
                key_ids = [key_ids]
            self.secrets = [{
                "sid": sid,
                "keyIDs": key_ids
            }]

    def get(self):
        if not self.secp:
            self.secp = {}

        if "name" not in self.secp:
            self.secp["name"] = self.name
        if "policyType" not in self.secp:
            self.secp["policyType"] = self.policyType

        if "designators" not in self.secp:
            self.secp["designators"] = self.designators

        if "secrets" not in self.secp:
            self.secp["secrets"] = self.secrets

        return self.secp

    def update_subsecrets(self, subsecrets: dict, sid: str = None):
        for secret in self.secrets:
            if sid:
                if sid == secret["sid"]:
                    for k, v in subsecrets:
                        secret["keyIDs"].append(
                            {
                                "subSecretName": k,
                                "keyID": v
                            }
                        )
            else:
                for k, v in subsecrets.items():
                    secret["keyIDs"].append(
                        {
                            "subSecretName": k,
                            "keyID": v
                        }
                    )
