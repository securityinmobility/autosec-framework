# Penetration Testing Automation

## First Automation Plan

The first drafts of the Autosec Framework were created with the plan to gather data during automotive penetration tests and to use this data with ML to automate the process. Therefore, a data-driven method was intended.

To be able to generate the necessary data, the plan was to create a MSF-like framework that shall be used to perform the penetration tests. The main focus was to integrarte the already available tools that are used (e.g. msf itself). The architecture therefore enables a flexible plug-in architecture into a core system. This core system is responsible to control the configuration and execution of all the modules while simultaneously the necessary (in first step all available) data is logged. To be able to use this system, defined interfaces and the matching programs for a CLI as well as a web based access were planned. 

## Related work regarding penetration testing automation

As most of the work of other researchers regarding the automation of penetration testing is not done by a data-driven method, this plan doesn't seem to be very promising. 

### Reinforced Learning Approach

Some related work  models the problem in a way to solve it by using reinforcement learning. This approach is promising if there is a fixed and bevorehand known target of the test. Within this setup the program is then able to start the test in a random way and then learn how to reach the target with the highest possible reward. As the reward usually decreases with more performed steps, this optimization usually also includes a faster method.


## Diskussion

-> Anmerkung Jakob: Warum das ganze nicht einfach in MSF implementieren, also dort weitere Module anlegen?
- Das Problem bei der Automatisierung liegt ja nicht unbedingt in einer "nutzerfreundlichen" Darstellung
- Das reine Implemenieren der Angriffe ist nicht zwingend die zentrale Voraussetzung (am Ende müssen die Angriffe implementiert sein)
- Um die Automatisierung zu schaffen, muss das Wissen über die Module vorhanden sein
- MSF bietet gewisse Funktionalitäten, die helfen können; allerdings ist es sehr auf Web-Angriffe forciert
- Die HW-Bridge kam erst 2017 dazu - seitdem auch recht wenige Automotive Module vorhanden (-> nochmal googlen, ob es hier Sammlungen etc gibt)
- Damit ergeben sich wohl nocht besonders viele Vorteile aus der Nutzung von MSF bzw. der Nutzung als Basissystem
