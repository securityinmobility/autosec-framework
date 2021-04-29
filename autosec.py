from core.app import App

class Autosec():
    def __init__(self, webApi = False, webApp = False):
        self.app = App(webApi, webApp)
        
    def start(self):
        self.app.start()

    def stop(self):
        self.app.stop()
        


if __name__ == "__main__":
    """ 
    By now simply start CLI only mode
    """
    app = Autosec()
    app.start()
