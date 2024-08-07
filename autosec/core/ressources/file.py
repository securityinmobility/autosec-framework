from .base import AutosecRessource

class FileArtifact(AutosecRessource):
    def __init__(self, file_path: str):
        self.file_path = file_path

    def get_file_path(self) -> str:
        return self.file_path
    
    def get_file_content(self) -> str:
        with open(self.file_path, 'r', encoding='utf-8') as file_to_read:
            content = file_to_read.read()
            return content
        
    def __eq__(self, other: object) -> bool:
        if isinstance(other, FileArtifact):
            return self.file_path == other.file_path
        return False