from enum import Enum

class Color(Enum):
    BLACK = 0
    RED = 1
    GREEN = 2
    YELLOW = 3
    BLUE = 4
    MAGENTA = 5
    CYAN = 6
    WHITE = 7
    STANDARD = 8

class Printer:
    def __init__(self):
        pass
    
    def printColored(self, msg, color):
        print(f"{__getColorCode(color)}{msg}{__getColorCode(Color.RESET)}")

    def printProgress(self, progress):
        pass    # Print a line with a reletive Progress(0-100)
    
    def __getColorCode(self, color):
        if not color == Color.STANDARD:
            return f"\u001b[3{color.value}m"
        else:
            return "\u001b[0m"