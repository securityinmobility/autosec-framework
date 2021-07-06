""" Main app of the AutoSec framework.

webApi: Not yet implemented, will start a REST API to control the framework
webApp: Not yet implemented, webApplication that can be used to control the framework.

Requires: webApi = True (error if it is set as false).
"""

from .log import Logger
from .interpreter import Interpreter

class App():
    '''
    Class that represents the main app
    '''
    def __init__(self):
        '''
        Initializes the main app module and its varibles
        '''

        self.log = Logger()
        self.interpreter = Interpreter()
        self.web_api = False
        self.web_app = False
        self.cli_app = False

    def start(self):
        '''
        Startup method for the app
        '''
        if self.web_api:
            self.log.w("Web Api is not yet implemented")
        if self.web_app:
            self.log.w("Web App is not yet implemented")
        if self.cli_app:
            self.log.w("CLI App is not yet implemendet")

    def stop(self):
        '''
        Stop method for the app
        '''
        self.interpreter.running = False
