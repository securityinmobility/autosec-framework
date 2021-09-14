from traitlets.config import Config
from IPython.terminal.prompts import Prompts, Token
import os

class IPythonConfig(Config):


    def __init__(self):
        self.InteractiveShellApp.exec_lines= [

        ]
 
