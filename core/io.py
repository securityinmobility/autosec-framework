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


def printColored(msg, color):
    print(f"{__getColorCode(color)}{msg}{__getColorCode(Color.STANDARD)}")

def printProgress(progress):
    pass    # Print a line with a reletive Progress(0-100)
    
def __getColorCode(color):
    if not color == Color.STANDARD:
        return f"\u001b[3{color.value}m"
    else:
        return "\u001b[0m"