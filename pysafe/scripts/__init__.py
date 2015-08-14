# builtin
import os
import sys
import json

# internal
from pysafe import utils

# Constants
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
HIDDEN_PASSWORD = "*" * 8

# Configuration and program storage
DATA_DIR = utils.abspath("~/.pysafe")
CONFIG_FILENAME = "conf.json"
DEFAULT_CONFIG_FILENAME = os.path.join(DATA_DIR, CONFIG_FILENAME)


class ArgumentError(Exception):
    """An exception to be raised when invalid or incompatible arguments are
    passed into the application via the command line.
    Args:
        show_help (bool): If true, the help/usage information should be printed
            to the screen.
    Attributes:
        show_help (bool): If true, the help/usage information should be printed
            to the screen.
    """
    def __init__(self, msg=None, show_help=False):
        super(ArgumentError, self).__init__(msg)
        self.show_help = show_help


def load_conf(fn=None):
    if not fn:
        fn = DEFAULT_CONFIG_FILENAME

    fn = utils.abspath(fn)

    try:
        with open(fn) as f:
            config = json.load(f)
    except IOError as ex:
        config = {}

    return config


def save_conf(config, fn=None):
    if not fn:
        fn = DEFAULT_CONFIG_FILENAME

    fn = utils.abspath(fn)

    with open(fn) as f:
        json.dump(config, f)


def print_record(record, hide=False):
    title = record.title
    group = record.group
    username = record.username
    password = record.password if not hide else HIDDEN_PASSWORD

    out = "[{}] '{}' '{}' '{}'"
    out = out.format(group, title, username, password)
    print out


def print_records(records, hide=False):
    for record in sorted(records, key=lambda x: str(x.group)):
        print_record(record, hide)


def init_logging(level="DEBUG"):
    import logging.config

    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'simple': {
                'format': '%(levelname)s $(asctime)s %(message)s'
            },
        },
        'handlers': {
            'console': {
                'level': level,
                'class': 'logging.StreamHandler',
                'formatter': 'simple'
            },
        },
        'loggers': {
            'pysafe': {
                'handlers': ['console'],
                'level': level,
                'propagate': True,
            },
        },
    }

    logging.config.dictConfig(config)