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