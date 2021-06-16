from core import log
import sys

'''Small Argument Parser that is specifically for the autosec framework'''

class ArgParser:
    def __init__(self, appInstance):
        self.appInstance = appInstance
        self.log = log.Logger()
    
    def parse(self):
        self._help()
        self._logLevel()
        self._wepApi()
        self._wepApp()
        self._cliApp()

    def _help(self):
        if self._getNamedFlag("-h") or self._getNamedFlag("--help"):
            pass    #implement help message (with sub-argument level?)

    def _logLevel(self):
        logLevel = self._getNamedArgument("--logLevel")
        if logLevel == None:
            return
        logLevel = logLevel.upper()
        if logLevel in log.Logger.logLevel.__members__:
            self.log.setLogLevel(log.Logger.logLevel[logLevel])

    def _wepApi(self):
        self.appInstance.webApi = self._getNamedFlag("--webApi")

    def _wepApp(self):
        self.appInstance.webApp = self._getNamedFlag("--webApp")
    
    def _cliApp(self):
        self.appInstance.cliApi = self._getNamedFlag("--cliApp")
        
    def _getNamedArgument(self, argument):
        try:
            index = sys.argv.index(argument) + 1
        except ValueError:
            return None
        if index >= len(sys.argv):
            return None
        return sys.argv[index]

    def _getNamedFlag(self, flag):
        if flag in sys.argv:
            return True
        else:
            return False

    def run(self):
        self.parse()
       