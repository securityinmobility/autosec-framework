#!/usr/bin/env python3
import logging
from autosec.core import app, arg_parser

def main():
    """ 
    By now simply start CLI only mode
    """
    App = app.App()
    arg_parser.ArgParser(App).run()
    try:
        App.start()
    except Exception as e:
        print(e)
