# HATS3 Documentation Repo

This repository shall be used to organize a part of the HATS3 documentation. 
As most of the documents shall be stored within the network drive (also organized as git repo), this repo is mainly for the documents regarding the parts, that have to be implemented (e.g. the Security Testing Framework itself).

In a later stage, this repository may be included within a source code reopository as doc/ directory.

## Create plantUML diagrams

The jar to create the plantUML diagrams is located under ./tools. Therefore, a plantUML diagram can be created by using*:

```
java -jar plantuml.jar PathToMyFile.puml
```
This is creating *.png files by default. Additional parameters can be found [here](https://plantuml.com/de/starting)


*: Java as well as Graphviz have to be installed and available in PATH / User-PATH
