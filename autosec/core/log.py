'''
TBD: Log file creation (with the python logging module)

'''
from enum import IntEnum
from .io import Color
from .io import print_colored

class Logger:
    '''
    Class that provides the logging functionality
    '''
    class LogLevel(IntEnum):
        '''
        Enumeration of the possible log-Levels
        '''
        DEBUG = 0
        INFO = 1
        WARNING = 2
        FAILURE = 3

    class _Logger:
        '''
        Private inner class that implements the logger
        Inner class is used to provide a single logging instance
        '''
        def __init__(self, log_level):
            '''
            Initialization of the logger
            '''
            self.set_log_level(log_level)

        def set_log_level(self, log_level):
            '''
            Set the logLevel
            '''
            self.log_level = log_level
            self.info(f"LogLevel set to {repr(log_level)}")

        def debug(self, msg):
            '''
            Send message in the debug level
            '''
            if self.log_level <= Logger.LogLevel.DEBUG:
                print_colored(msg, Color.STANDARD)
        def info(self, msg):
            '''
            Send message in the info level
            '''
            if self.log_level <= Logger.LogLevel.INFO:
                print_colored(msg, Color.STANDARD)
        def warning(self, msg):
            '''
            Send message in the warning level
            '''
            if self.log_level <= Logger.LogLevel.WARNING:
                print_colored(msg, Color.YELLOW)
        def failure(self, msg):
            '''
            Send message in the failure level
            '''
            if self.log_level <= Logger.LogLevel.FAILURE:
                print_colored(msg, Color.RED)

    instance = None

    def __init__(self, logLevel = LogLevel.WARNING):
        '''
        Initializes the outer class
        '''
        if not Logger.instance:
            Logger.instance = Logger._Logger(logLevel)
            #The logLevel is set once during the initial creation of the Logger.
            #Afterwards only an implicit call can change it - not the constructor
    def __getattr__(self, name):
        '''
        Makes the inner class accessible via the outer class
        '''
        return getattr(self.instance, name)

    def get_instance(self):
        '''
        returns the logging classes instance
        '''
        return self.instance
