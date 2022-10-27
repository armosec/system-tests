class WorkloadEncryptionConfiguration(object):
    def __init__(self, key_id: str, path: str, container: str, wlid: str = None, gradual_encryption=False,
                 gradual_decryption=False, exclude: str = ""):
        super().__init__()
        self.wlid = wlid
        self.key_id = key_id
        self.path = path
        self.exclude = exclude
        self.container = container
        self.gradual_encryption = gradual_encryption
        self.gradual_decryption = gradual_decryption

    def get(self):
        return {
            "wlid": self.wlid,
            "keyID": "",
            "gradualEncryption": 0,
            "gradualDecryption": 0,
            "containers": {
                self.container: {
                    "directories": [
                        {
                            "keyID": self.key_id,
                            "gradualEncryption": 1 if self.gradual_encryption else -1,
                            "gradualDecryption": 1 if self.gradual_decryption else -1,
                            "path": self.path,
                            "exclude": self.exclude
                        }
                    ],
                    "volumes": [],
                    "regexps": [],
                }
            }
        }
