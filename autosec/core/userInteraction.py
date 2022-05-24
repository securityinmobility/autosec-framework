from abc import ABC, abstractmethod
from typing import List
"""
Basic interface to handle user interactions. 
"""

class userInteraction(ABC):

    _answer = ""
    _question = ""
        

    @staticmethod
    def setQuestion(self, question):
        self._question = question

    @staticmethod
    def getQuestion(self):
        return self._question

    @staticmethod
    def getAnswer(self):
        return self._answer

    @abstractmethod
    def yesNoAnswer(self) -> str:
        """
        Method to ask the user a yes/no question
        """
        raise NotImplementedError

    @abstractmethod
    def integerAnswer(self) -> int:
        """
        Method to ask the user a question where the answer should be an integer
        """
        raise NotImplementedError

    @abstractmethod
    def stringAnswer(self) -> str:
        """
        Method to ask the user a question where the answer should be string
        """
        raise NotImplementedError

    @abstractmethod
    def checkListAnswer(self, inputs: List[str]) -> List[str]:
        """
        Method to ask the user a question where he can choose from a list of answeres
        """
        raise NotImplementedError

    @abstractmethod
    def feedback(self, feedback : str):
        """
        Method to provide feedback to the user if e.g. an attack has failed/succeeded
        """
        raise NotImplementedError

    

    