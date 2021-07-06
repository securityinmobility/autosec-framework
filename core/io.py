'''
This module implements functionality to interact with the user over the cli
'''

from enum import Enum

class Color(Enum):
    '''
    Class that enumerates the different colors that can be used in a basic shell
    '''
    BLACK = 0
    RED = 1
    GREEN = 2
    YELLOW = 3
    BLUE = 4
    MAGENTA = 5
    CYAN = 6
    WHITE = 7
    STANDARD = 8


def print_colored(msg, color):
    '''
    Print a message in the shell with the specified color
    '''
    print(f"{__get_color_code(color)}{msg}{__get_color_code(Color.STANDARD)}")

def print_progress(progress):
    '''
    This method shall be used to print a progress from 0-100%
    '''
    # Print a line with a reletive Progress(0-100)
    print(f"{progress}% / 100 %")

def __get_color_code(color):
    '''
    Private method that is used to get the color code of a specific color
    '''
    if not color == Color.STANDARD:
        return f"\u001b[3{color.value}m"
    return "\u001b[0m"
