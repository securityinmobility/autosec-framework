from core import app, argParser

if __name__ == "__main__":
    """ 
    By now simply start CLI only mode
    """
    app = app.App()
    parser = argParser.ArgParser(app)
    parser.run()
    try:
        app.start()
    except KeyboardInterrupt:
        app.stop()
        