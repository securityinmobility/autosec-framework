from autosec.core.ressources import AutosecRessource, NetworkInterface


class ObdInfo(AutosecRessource):

    def __init__(self, info , service, id):
        super().__init__()
        self.info = info
        self.service = service
        self.id = id

    def getInfo(self) -> dict:
        return self.info
    
    def getService(self):
        return self.service

    def getIdOfService(self):
        return self.id
    
