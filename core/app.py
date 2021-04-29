
class App():
    def __init__(self, webApi, webApp):
        """ Main app of the AutoSec framework.

        webApi: Not yet implemented, will start a REST API to control the framework
        webApp: Not yet implemented, webApplication that can be used to control the framework.

        Requires: webApi = True (error if it is set as false).
        """

        self.webApi = webApi
        if webApp and not webApi:
            print("WebApp is active but Api is not. Both will be enabled")
            self.webApi = True
        self.webApp = webApp

    def start(self):
        pass

    def stop(self):
        pass