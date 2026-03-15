import requests
import urllib3
import os

urllib3.disable_warnings()

class WazuhClient:
    def __init__(self):
        self.base_url = "https://localhost:55000"
        self.username = os.getenv("WAZUH_USER", "wazuh")
        self.password = os.getenv("WAZUH_PASSWORD")

        if not self.password:
            raise RuntimeError("WAZUH_PASSWORD not set")

        self.token = self._authenticate()

    def _authenticate(self):
        url = f"{self.base_url}/security/user/authenticate"
        response = requests.post(
            url,
            auth=(self.username, self.password),
            verify=False
        )
        response.raise_for_status()
        return response.json()["data"]["token"]

    def get(self, endpoint, params=None):
        headers = {
            "Authorization": f"Bearer {self.token}"
        }
        response = requests.get(
            f"{self.base_url}{endpoint}",
            headers=headers,
            verify=False,
            params=params
        )
        response.raise_for_status()
        return response.json()
