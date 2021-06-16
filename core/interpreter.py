from .log import Logger

''' Simple Interpreter to create a interactive application
'''

class Interpreter:
    def __init__(self):
        self.log = Logger()
        self.running = True

    def unknown(self):
        '''
        Method to be called if an unknown command was entered
        '''
        self.log.w("Unknown Command")

    def loop(self):
        while self.running:
            pass