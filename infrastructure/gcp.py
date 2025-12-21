import json
import time
from googleapiclient.discovery import build
from google.oauth2 import service_account

class GcpManager:
    def __init__(self, service_account_key_json: str):
        self.service_account_key = json.loads(service_account_key_json) if isinstance(service_account_key_json, str) else service_account_key_json
        self.project_id = self.service_account_key.get("project_id")
        self.service_account_email = self.service_account_key.get("client_email")
        self.credentials = service_account.Credentials.from_service_account_info(
            self.service_account_key,
            scopes=['https://www.googleapis.com/auth/cloud-platform']
        )
        self.service = build('cloudresourcemanager', 'v1', credentials=self.credentials)

    def _get_iam_policy(self):
        return self.service.projects().getIamPolicy(resource=self.project_id).execute()

    def _set_iam_policy(self, policy):
        body = {'policy': policy}
        return self.service.projects().setIamPolicy(resource=self.project_id, body=body).execute()

    def remove_role(self, role: str):
        """Removes a specific role from the service account."""
        policy = self._get_iam_policy()
        member = f"serviceAccount:{self.service_account_email}"
        
        modified = False
        for binding in policy.get('bindings', []):
            if binding['role'] == role and member in binding.get('members', []):
                binding['members'].remove(member)
                modified = True
        
        if modified:
            self._set_iam_policy(policy)
            print(f"Role {role} removed. Waiting for propagation...")
            # IAM changes can take a few seconds to propagate in GCP
            time.sleep(5) 
        return modified

    def add_role(self, role: str):
        """Adds a specific role back to the service account."""
        policy = self._get_iam_policy()
        member = f"serviceAccount:{self.service_account_email}"
        
        for binding in policy.get('bindings', []):
            if binding['role'] == role:
                if member not in binding['members']:
                    binding['members'].append(member)
                return self._set_iam_policy(policy)

        # If role binding doesn't exist at all
        policy.get('bindings', []).append({'role': role, 'members': [member]})
        return self._set_iam_policy(policy)