from autosec.core.ressources import AutosecRessource, NetworkInterface


class ObdInfo(AutosecRessource):

    def __init__(self, info):
        super().__init__()
        self.info = info

    def getInfo(self) -> dict:
        return self.info
    
