
class InvalidPasswordError(ValueError):
    pass


class KeyLookupError(KeyError):
    def __init__(self, message=None, key=None):
        super(KeyLookupError, self).__init__(message)
        self.key = key


class ArgumentError(ValueError):
    def __init__(self, message, show_help=True):
        super(ArgumentError, self).__init__(self, message)
        self.show_help = show_help
