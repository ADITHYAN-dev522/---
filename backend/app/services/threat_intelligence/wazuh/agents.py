from .wazuh_client import WazuhClient

def get_wazuh_agents():
    client = WazuhClient()
    return client.get("/agents")
