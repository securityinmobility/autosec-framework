from core.autosecModule import AutosecModule
import json


class msfModule(AutosecModule):
    def __init__(self, Client, Module):
        self._client=Client
        self._module=Module
        
        self._name=Module.modulename
        self._type=Module.moduletype
        self._source="msf"
        self._description=Module.description

        options = Module.options
        self._options={}
        for opt in options:
            self._options[opt] = Module.optioninfo(opt)
        
    def getInfo(self):
        return dict(
            name = self._name,
            source = self._source,
            type = self._type,
            description = self._description
            )

    def getOptions(self):
        return self._options
    
    def setOption(self, values):
        for key in values:
            try:
                reqType = self._getType(self._options[key]["type"])
                if not type(values[key]) == reqType:
                    print(f"Value {values[key]} is wrong type for option {key}. Required is {reqType}")
                    raise ValueError
                self._options[key]["value"] = values[key]
            except ValueError:
                print(f"Could not store value for key {key}")

        self._update()

    def getRunOptions(self):
        return self._module.runioptions()

    def ready(self):
        return (len(self._module.missing_required()) == 0)

    def run(self, runOps = None):
         return self._module.execute(runOps)
 
    def _update(self):
        opts = {}
        for key in self._options:
            value = self._options[key]["value"]
            if not value == None:
                opts[key] = value
        self._module.update(opts)

    def _getType(self, Type):
        switcher=dict(
            integer = int,
            bool = bool,
            float = float,
            string = str
            )
        try: 
            return switcher[Type]
        except ValueError:
            return str  #default value


