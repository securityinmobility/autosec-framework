#!/usr/bin/env python3
from autosec.core import app, arg_parser

def main():
    """
    By now simply start CLI only mode
    """
    autosec_app = app.App()
    arg_parser.ArgParser(autosec_app).run()
    autosec_app.start()
