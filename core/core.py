'''
Core Module to organize necessary tasks
'''
from core import module_loader

class Core:
    '''
    Class to organize the necessary tasks within the frameworks lifecycle
    '''
    def __init__(self):
        '''
        Initialize the core module
        '''
        print("Loading available modules")
        self.modules = module_loader.loadAvailableModules()
        print("Loading modules finished")

    def get_moduels(self):
        '''
        Method to retrieve the loaded modules
        '''
        return self.modules.copy()

    def get_module_number(self):
        '''
        Return the number of the loaded modules
        '''
        return len(self.modules)
