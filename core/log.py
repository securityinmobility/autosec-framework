from io import Printer.printColored, Color
from enum import Enum

class Logger:
    class logLevel(Enum):
        DEBUG = 0
        EVENT = 1
        WARNING = 2
        FAILURE = 3

    class __Logger:
        def __init__(self, logLevel):
            setLogLevel(logLevel)

        def setLogLevel(self, logLevel):
            self.logLevel = logLevel

        def d(self, msg):
            if self.logLevel <= logLevel.DEBUG:
                printColored(msg, Color.STANDARD)
        def e(self, msg):
            if self.logLevel <= logLevel.EVENT:
                printColored(msg, Color.STANDARD)
        def w(self, msg):
            if self.logLevel <= logLevel.WARNING:
                printColored(msg, Color.YELLOW)
        def f(self, msg):
            if self.logLevel <= logLevel.FAILURE:
                printColored(msg, Color.RED)

    instance = None

    def __init__(self, logLevel = logLevel.WARNING):
        if not Logger.instance:
            Logger.instance = Logger.__Logger(logLevel) #The logLevel is set once during the initial creation of the Logger. Afterwards only an implicit call can change it - not the constructor
    def __getattribute__(self, name):
        return getattr(self.instance(name))

    