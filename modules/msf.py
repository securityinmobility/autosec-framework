from Msf.MsfClient import msfClient

def load_module():
    client = msfClient()
    return client.getModules()
