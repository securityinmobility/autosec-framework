""" Main app of the AutoSec framework.

webApi: Not yet implemented, will start a REST API to control the framework
webApp: Not yet implemented, webApplication that can be used to control the framework.

Requires: webApi = True (error if it is set as false).
"""
import logging
import autosec.core.utils as utils
import IPython 
from traitlets.config import Config


class App():
    '''
    Class that represents the main app
    '''
    def __init__(self):
        '''
        Initializes the main app module and its varibles
        '''

        utils.set_top_log_level("DEBUG")

        ##Get Own Logger##
        self.logger = logging.getLogger("autosec.core.app")
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("New App Instance Created")

        self.web_api = False
        self.web_app = False
        self.cli_app = False
        self.disable_auto_load = False

    def start(self):
        '''
        Startup method for the app
        '''
        if self.web_api:
            self.log.w("Web Api is not yet implemented")
        if self.web_app:
            self.log.w("Web App is not yet implemented")
        if not self.disable_auto_load:
            self.modules = utils.load_available_modules()

        IPython.embed()


    def stop(self):
        '''
        Stop method for the app
        '''
        exit()

    def _create_ipython_config(self):

        config = Config()
        config.InteractiveShellApp.exec_lines= [

        ]
