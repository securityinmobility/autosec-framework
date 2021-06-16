from .log import Logger
from .interpreter import Interpreter

class App():
    def __init__(self):
        """ Main app of the AutoSec framework.

        webApi: Not yet implemented, will start a REST API to control the framework
        webApp: Not yet implemented, webApplication that can be used to control the framework.

        Requires: webApi = True (error if it is set as false).
        """

        self.log = Logger()
        self.interpreter = Interpreter()
        self.webApi = False
        self.webApp = False
        self.cliApp = False

    def start(self):
        if self.webApi:
            self.log.w("Web Api is not yet implemented")
        if self.webApp:
            self.log.w("Web App is not yet implemented")
        if self.cliApp:
            self.log.w("CLI App is not yet implemendet")

    def stop(self):
        self.interpreter.running = False