'''
This is where the configurations for the IPython can be made. 
All possible configurations can be found here: https://ipython.readthedocs.io/en/stable/config/options/terminal.html
'''
from traitlets.config import Config
from IPython.terminal.prompts import Prompts, Token

class IPythonConfig(Config):
    '''
    Class to edit all IPython configurations
    '''
    def __init__(self):

        shell = self.InteractiveShell
        shellEmbed = self.InteractiveShellEmbed
        shellApp = self.InteractiveShellApp

        # set the prompts
        shell.prompts_class = UIPrompt
        # set code to run at the startup
        shellApp.exec_lines = []

        # set banner before the profile
        shell.banner1 = "First banner" # default: "Python 3.8.11 (default, Aug  3 2021, 15:09:35) \\nType 'copyr..."
        # set banner after the profile 
        shell.banner2 = "Second banner" # default: None
       
        # set whether colors for displaying informations should be used 
        shell.color_info = True
        # set color scheme
        shellEmbed.colors = 'LightBG' # Possible: 'Neutral','NoColor','LightBG','Linux'
        shell.highlight_matching_brackets = True 

        shell.cache_size = 1010 # default 1000
        shell.history_length = 1000 # default 10000
        
        # e.g. for autocall 
        shell.show_rewritten_input = True 
        # set autoindent interactively entered code 
        shell.autoindent = True
        # set editor
        shell.editor = 'nano'
        

class UIPrompt(Prompts):
    '''
    Class that provides functions to edit the in / out / continuation / rewrite 
    prompts for the ui. 
    '''
    def in_prompt_tokens(self, cli=None):
        return [(Token.Prompt, '>>>')]
    
    def out_prompt_tokens(self, cli=None):
        return [(Token.Prompt, '<<<')]

    # def continuation_prompt_tokens(self, cli=None, width=None):

    # def rewrite_promt_tokens(self, cli=None):