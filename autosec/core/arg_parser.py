'''
Small Argument Parser that reads the command line arguements
'''

import sys
import logging
import autosec.core.utils as utils

class ArgParser:
    '''
    Class that is responsible to parse the arguments
    '''
    def __init__(self, app_instance):
        '''
        Initializes the needed variables
        '''
        self.app_instance = app_instance
        self.logger = logging.getLogger("autosec.core.argparser")
        self.logger.setLevel(logging.DEBUG)

    def parse(self):
        '''
        Method that is called at the startup. Dispatches the parsing to the single methods
        '''
        self._help()
        self._log_level()
        self._wep_api()
        self._wep_app()
        self._cli_app()

    def _help(self):
        '''
        Method that returns a help message
        '''
        if self._get_named_flag("-h") or self._get_named_flag("--help"):
            pass    #implement help message (with sub-argument level?)

    def _log_level(self):
        '''
        Method to parse the needed log-Level
        '''
        log_level = self._get_named_argument("--logLevel")
        if log_level is None:
            return
        log_level = log_level.upper()
        utils.set_top_log_level(log_level)
        self.logger.debug(f"logLevel set to {log_level}")

    def _wep_api(self):
        '''
        Method that parses the flag for the web_api
        '''
        self.app_instance.web_api = self._get_named_flag("--webApi")

    def _wep_app(self):
        '''
        Method that parses the flag for the web_app
        '''
        self.app_instance.web_app = self._get_named_flag("--webApp")

    def _cli_app(self):
        '''
        Method that parses the flag for the cli_api
        '''
        self.app_instance.cli_api = self._get_named_flag("--cliApp")

    @classmethod
    def _get_named_argument(cls, argument):
        '''
        Method that searches for the specified argument and return the value
        argument: Named argument that has to be searched
        return: value of the argument, None if the arguemnt is not specified
        raises: ValueError if there is a problem with the specified argument
        '''
        try:
            index = sys.argv.index(argument) + 1
        except ValueError:
            return None
        if index >= len(sys.argv):
            return None
        return sys.argv[index]

    @classmethod
    def _get_named_flag(cls, flag):
        '''
        Method that searches for a flag
        flag: name of the flag that shall be checked
        returns: True if flag is specified, False if not
        '''
        if flag in sys.argv:
            return True
        return False

    def run(self):
        '''
        Method to start the parsing process
        '''
        self.parse()
       