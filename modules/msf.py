'''Module to provide the metasploit framework modules'''
from modules.Msf.MsfClient import msfClient

def load_module():
    '''Provides a list of all msf modules'''
    client = msfClient()
    #return client.getModules()
    return []
