'''Client to communicate with the msf framework running on the host system'''
from pymetasploit3.msfrpc import MsfRpcClient
from .msfModule import msfModule
import subprocess 
import random
import string


class msfClient():
    def __init__(self):
        self.startMsf()
        self._modules = None

    def startMsf(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(alphabet) for i in range(16))
        command = ["msfrpcd", "-P", password]
        subprocess.Popen(command)
        self._client = MsfRpcClient(password, ssl=True)

    def getModules(self):


        availableModules = []
        exploits = self._client.modules.exploits
        # The following module causes a freeze within the pymetasploit3 lib
        exploits.remove("linux/misc/saltstack_salt_unauth_rce")
        auxiliary = self._client.modules.auxiliary
        post = self._client.modules.post
        payloads = self._client.modules.payloads
        encoders = self._client.modules.encoders
        nops = self._client.modules.nops
        evasion = self._client.modules.evasion

        totSize = len(exploits)+len(auxiliary)+len(post)+len(payloads)+len(encoders)+len(nops)#+len(evasion)
        ctr = 0
        print(f"Loading {len(exploits)} Exploits")
        for exp in exploits:
            ctr = ctr + 1
            print(f"Loading module {ctr} / {totSize}", end="\r")
            availableModules.append(msfModule(self, self._client.modules.use('exploit', exp)))
        print(f"Exploits loading finished. Loading {len(auxiliary)} auxiliaries")
        for aux in auxiliary:
            ctr = ctr + 1
            print(f"Loading module {ctr} / {totSize}", end="\r")
            availableModules.append(msfModule(self, self._client.modules.use('auxiliary', aux)))
        print(f"Auxiliaries loading finished. Loading {len(post)} posts")
        for pos in post:
            ctr = ctr + 1
            print(f"Loading module {ctr} / {totSize}", end="\r")
            availableModules.append(msfModule(self, self._client.modules.use('post', pos)))
        print(f"Posts loading finished. Loading {len(payloads)} payloads")
        for pay in payloads:
            ctr = ctr + 1
            print(f"Loading module {ctr} / {totSize}", end="\r")
            availableModules.append(msfModule(self, self._client.modules.use('payload', pay)))
        print(f"Payloads loading finished. Loading {len(encoders)} encoders")
        for enc in encoders:
            ctr = ctr + 1
            print(f"Loading module {ctr} / {totSize}", end="\r")
            availableModules.append(msfModule(self, self._client.modules.use('encoder', enc)))
        print(f"Encoders loading finished. Loading {len(nops)} nops")
        for nop in nops:
            ctr = ctr + 1
            print(f"Loading module {ctr} / {totSize}", end="\r")
            availableModules.append(msfModule(self, self._client.modules.use('nop', nop)))
        print(f"Nops loading finished. {len(evasion)} evasions are currently not loaded as they're not yet supported. {totSize} modules loaded.")
        """for eva in evasion:
            ctr = ctr + 1
            print(f"Loading module {ctr} / {totSize}", end="\r")
            availableModules.append(msfModule(self, self._client.modules.use('evasion', eva)))
        print(f"Evasions loading finished. All {totSize} modules loaded.")"""

        availableModulesDict = {}
        for module in availableModules:
            availableModulesDict[f"msf.{module.getInfo()['name']}"] = module
        return availableModulesDict
    
