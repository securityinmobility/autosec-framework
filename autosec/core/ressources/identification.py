from autosec.core.ressources.base import AutosecRessource


class Identification(AutosecRessource):
    def __init__(self, identification: str):
        self.identification = identification

    def get_identification(self) -> str:
        return self.identification
    
    def __eq__(self, value: object) -> bool:
        if isinstance(value, Identification):
            return self.get_identification() == value.get_identification()
        return False