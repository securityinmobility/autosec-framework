from autosec.core.ressources import AutosecRessource, NetworkInterface
from scapy.all import conf, load_contrib

load_contrib("automotive.obd.obd")

class ObdInfo(AutosecRessource):

    def __init__(self, info, service, id):
        super().__init__()
        self.info = info
        self.service = service
        self.id = id

    def get_info(self) -> dict:
        return self.info
    
    def get_service(self):
        return self.service

    def get_id_of_service(self):
        return self.id