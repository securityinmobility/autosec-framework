""" Main app of the AutoSec framework.

webApi: Not yet implemented, will start a REST API to control the framework
webApp: Not yet implemented, webApplication that can be used to control the framework.

Requires: webApi = True (error if it is set as false).
"""
import sys
import logging
import IPython
from traitlets.config import Config

from autosec.core import utils


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

    def start(self):
        '''
        Startup method for the app
        '''
        if self.web_api:
            self.logger.warning("Web Api is not yet implemented")
        if self.web_app:
            self.logger.warning("Web App is not yet implemented")

        IPython.embed()

    @staticmethod
    def stop():
        '''
        Stop method for the app
        '''
        sys.exit()

    @staticmethod
    def _create_ipython_config():

        config = Config()
        config.InteractiveShellApp.exec_lines= [

        ]
