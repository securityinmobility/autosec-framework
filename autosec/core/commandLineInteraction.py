import sys
from typing import List

from autosec.core.UserInteraction import UserInteraction


class CommandLineInteraction(UserInteraction):
    """
    class that provides a command line user interaction interface
    """

    def __init__(self):
        super().__init__()

    def yesNoAnswer(self) -> str:
        print(self.getQuestion() + "\t [y]es, [n]o \n")
        answer = str(sys.argv[1])
        if answer not in ["y", "n"]:
            print("Please choose from: [y]es, [n]o \n")
            answer = self.yesNoAnswer()
        self._answer = answer
        return answer

    def stringAnswer(self) -> str:
        print(self.getQuestion() + "\n")
        answer = str(sys.argv[1])
        self._answer = answer
        return answer

    def integerAnswer(self) -> int:
        print(self.getQuestion() + "\n")
        try:
            answer = int(sys.argv[1])
        except:
            print("Please only input numbers. \n")
            answer = self.integerAnswer()
        self._answer = answer
        return answer

    def checkListAnswer(self, inputs: List[str]) -> str:
        print(self.getQuestion() + "\n")
        print("Options to choose from: \n")
        for option in range(len(inputs)):
            print("%s \t %s" % (option, inputs[option]))
        answer = int(sys.argv[1])
        if answer not in [i for i in range(len(inputs))]:
            print("Please only select number between %s and %s \n" % (0, len(inputs)))
            answer = self.checkListAnswer(inputs)
        self._answer = answer
        return answer

    def feedback(self, feedback: str):
        print(feedback)
