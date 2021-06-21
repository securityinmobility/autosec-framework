from pymetasploit3.msfrpc import MsfRpcClient
from Msf.msfModule import msfModule
import subprocess, random, string

class msfClient():    
    def __init__(self):
        self.startMsf()
        self._modules = None

    def startMsf(self):
        sessionPassword = pw = ''.join(random.choice(string.ascii_letters+string.digits+string.punctuation) for i in range(16))
        startCommand = ["msfrpcd", "-P", sessionPassword]
        subprocess.Popen(startCommand)
        self._client = MsfRpcClient(sessionPassword, ssl=True)

    def getModules(self):


        availableModules = []
        exploits = self._client.modules.exploits
        exploits.remove("linux/misc/saltstack_salt_unauth_rce")     #This module causes a freeze within the pymetasploit3 lib
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
    