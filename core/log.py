from .io import Color, printColored
from enum import IntEnum

'''
TBD: Log file creation (with the python logging module)

'''

class Logger:

    class logLevel(IntEnum):
        DEBUG = 0
        INFO = 1
        WARNING = 2
        FAILURE = 3

    class __Logger:
        def __init__(self, logLevel):
            self.setLogLevel(logLevel)

        def setLogLevel(self, logLevel):
            self.logLevel = logLevel

        def d(self, msg):
            if self.logLevel <= Logger.logLevel.DEBUG:
                printColored(msg, Color.STANDARD)
        def i(self, msg):
            if self.logLevel <= Logger.logLevel.INFO:
                printColored(msg, Color.STANDARD)
        def w(self, msg):
            if self.logLevel <= Logger.logLevel.WARNING:
                printColored(msg, Color.YELLOW)
        def f(self, msg):
            if self.logLevel <= Logger.logLevel.FAILURE:
                printColored(msg, Color.RED)

    instance = None

    def __init__(self, logLevel = logLevel.WARNING):
        if not Logger.instance:
            Logger.instance = Logger.__Logger(logLevel) #The logLevel is set once during the initial creation of the Logger. Afterwards only an implicit call can change it - not the constructor
    def __getattr__(self, name):
        return getattr(self.instance, name)
    
    def getInstance(self):
        return self.instance

    