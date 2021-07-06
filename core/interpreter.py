'''
Simple Interpreter to create a interactive application
'''
from .log import Logger

class Interpreter:
    '''
    Class that provides the functionality of an interpreter
    '''
    def __init__(self):
        '''
        Initializes the interpreter
        '''
        self.log = Logger()
        self.running = True

    def unknown(self):
        '''
        Method to be called if an unknown command was entered
        '''
        self.log.w("Unknown Command")

    def loop(self):
        '''
        Main loop of the interpreter
        '''
        while self.running:
            pass
