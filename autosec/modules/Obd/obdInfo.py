from autosec.core.ressources import AutosecRessource, NetworkInterface


class ObdInfo(AutosecRessource):

    def __init__(self, info, data):
        super().__init__()
        self.infoDict = info
        self.rawDataDict = data

    def getInfo(self) -> dict:
        return self.infoDict
    
    def getData(self) -> dict:
        return self.rawDataDict