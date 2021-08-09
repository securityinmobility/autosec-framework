# Autosec Module Development Guide
This guide is meant to be used by any person that wants (or has to) implement a module for the autosec penetration testing framework. The following information should be sufficient to implement these modules, to integrate them into the framework and to succuessfully collaborate in the github project.

## Change Log

Date | Author | Changes
--- | --- | ---
07.07.2021 | Marco Michl | Initial creation, description of installation, logging, repo and CI-Structure

## Installation

To use the framework (and to develop a own module) the needed libs have to be installed (additional to python itself). To install these libs, simply run the command ```pip install -r requirements.txt```. If there are any additional libs needed in newly created modules, the reuquirements.txt file should be updated and (carefully) merged. The usage of a virtual environment for this project is advised to ease the update of the requirements.txt file.

## Repo and CI Structure

As the students of the THI are not able to access the CARISSMA GitLab server, the project is hosted on [github.com](https://github.com/marcomichl/autosec-framework). As of now, the project is private and the authors are individually authorized to access the project. For this purpose they have to create a github account.

To be able to collaborate, each student shall create its own development branches to create their modules. The branches can be merged into the master branch at any time. As soon as there is a push to the master branch, several Github-actions are triggered. These actions mainly check the code style by applying [pylint](https://pypi.org/project/pylint/). Additionally the implementes tests are executed by [pytest](https://docs.pytest.org/en/6.2.x/). If the code style check fails, the tests are not executed. To reduce the number of pushes that result in failed tests, each contributer should check if the executed tests fail bevore the code is pushed to the master branch. This can be done by performing `pylint` and `pytest` in the main directory of the framework. A script that can be used to perform these tests locally will be created (at some moment in the future).

## Module Interface

The module interface is implemented in the autosec/core/autosec_module.py module. The modules itself can inherit from the class within this file and therfore use the methods that are already implemented.

By now the framework itself is not calling any of the methods described in the interface. Therefore the modules can implement a different interface - but this is not recommended as the automatisation of the tests is a target of the autosec framework.

The main methods are described in the following sections.

### \_\_init\_\_
The \_\_init\_\_ method is used as it is within standard python code. By inheriting the super-init method with `super().__init__()`, the logging instance (`self.logger`) and an empty dictionary for options is created.

### get_info

This method is not implemented in the interface description. It shall simply return a dict with the most relevant information about the module like the name, what interfaces (CAN, Ethernet...), a short description...

### get_options

By calling this method, a copy of the current options is returned. As it is a copy, it shall can not be modified directly.

### set_options

The modification of the options can be done by the set_options method. This method accepts multiple arguments that consist of key / value pairs. The key is the name of the option in the internal dictionary, the value will be places in the value field.
An example for the can_bridge module:
```python
module.set_option(("primaryInterface", "vcan0"), ("secondaryInterface", "vcan1"), ("filters", ([lambda id, data: (True, None, None)][]])))
```
This call sets three options: primary and secondary interface and one filter.

### \_add_option

To add options that work with the set_options mehthod, \_add_options can be used. This adds an option to the internal dictionary, that contains all necessary fields. Only the name is required, all other fields are optional.

### run

To start the functionality of a module, run shall be called. By calling the super-run method, a check if all necessary options are set is performed (within this step, the default values are applied).

## Logging

The core part of the framework (autosec.core) configures a standard [python logger](https://docs.python.org/3/howto/logging.html) that pipes the logging messages together with the time, the module and the level into a file (/logfiles/autosec.log) as well to stderr.

Each module should create its own logging instance with a own name that takes place in the logging hierarchy (`autosec.module.XXX`). After the creation of the logger the used log-level can be configured. The following lines can be used to create a logger for the module "example" with the log-level INFO:
```python
logger = logging.getLogger("autosec.module.example")
logger.setLevel(logging.INFO)
```
The preconfigured top-level-logger (`autosec`) can be configured with the command line argument `--logLevel` and therfore sets the minimum level of messages that can be logged for the whole application. The standard log levels of the python logging module are used. Therfore, the standard methods can be used after the logger has been created:
```python
logger.debug("Debug Message")
logger.info("Info Message")
logger.warning("Warning Message")
logger.error("Error Message")
logger.critical("Critical Message")
logger.exception("Exception message, also prints a stacktrace")
```