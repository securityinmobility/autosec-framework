'''
This is where the configurations for the (Core-)IPython-UI can be made. 
'''
from traitlets.config import Config
from IPython.terminal.prompts import Prompts, Token

class IPythonConfig(Config):
    '''
    Class to edit all IPython configurations
    '''
    def __init__(self):
        # set the prompts
        self.InteractiveShell.prompts_class = UIPrompt


class UIPrompt(Prompts):
    '''
    Class that provides functions to edit the in / out / continuation / rewrite 
    prompts for the ui. 
    '''
    def in_prompt_tokens(self, cli=None):
        return [(Token.Prompt, '>>>')]

    # def continuation_prompt_tokens(self, cli=None, width=None):

    # def rewrite_promt_tokens():

    # def out_prompt_tokens():