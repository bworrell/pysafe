#!/usr/bin/env python

# stdlib
import sys
import argparse
import logging

# external
import pyperclip

# internal
from pysafe import db
from pysafe import errors
from pysafe import scripts
from pysafe import utils
from pysafe.version import __version__


LOG = logging.getLogger(__name__)


def get_arg_parser():
    version = __version__
    parser = argparse.ArgumentParser(
        description="pwsr-get version {0}".format(version)
    )

    parser.add_argument(
        "--db",
        dest="dbfn",
        default=None,
        help="Path to PasswordSafe Database File"
    )

    parser.add_argument(
        "--dbpw",
        dest="dbpw",
        default=None,
        help="PasswordSafe Database key"
    )

    parser.add_argument(
        "--hide",
        dest="hide",
        default=False,
        action="store_true",
        help="Replace password with *'s"
    )

    parser.add_argument(
        "--list",
        dest="list",
        default=False,
        action="store_true",
        help="List Password Safe entries"
    )

    parser.add_argument(
        "key",
        metavar="KEY",
        nargs="?",
        default=None,
        help="Password Safe entry key (Example: gmail)"
    )

    return parser


def validate_params(argparser, **kwargs):
    args = kwargs['args']

    if not (kwargs['dbfn'] and kwargs['dbpw']):
        error = "Must provide both a pwsafe database and a password either."
        raise errors.ArgumentError(error, show_help=True)

    if not (kwargs['key'] or args.list):
        error = "Must provide a pwsafe key to look up, or --list"
        raise errors.ArgumentError(error, show_help=True)


def copy_password(password):
    pyperclip.copy(str(password))


def handle_ex(ex, stacktrace=False):
    if stacktrace:
        LOG.exception(ex)
    else:
        LOG.error(str(ex))

    sys.exit(scripts.EXIT_FAILURE)


def main():
    # Parse the commandline arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # initialize logging
    scripts.init_logging()

    # Attempt to load a pwsafe-remote configuration file
    config  = scripts.load_conf()

    # Extract pwsafe-remote parameters
    dbfn    = args.dbfn or config.get('PWDB')
    dbfn    = utils.abspath(dbfn)
    dbpw    = args.dbpw or config.get('PWDB_KEY')
    key     = args.key
    hide    = args.hide

    try:
        # Attempt to validate input parameters
        validate_params(argparser, dbfn=dbfn, dbpw=dbpw, key=key, args=args)

        # Parse the pwsafe database
        pwsafe = db.parse(dbfn, dbpw)

        if args.list:
            scripts.print_records(pwsafe, hide)
        else:
            # Find record
            record = utils.find(pwsafe, key)
            scripts.print_record(record, hide)
            copy_password(record.password)
    except Exception as ex:
        if getattr(ex, "show_help", False):
            argparser.print_help()
        handle_ex(ex)

    sys.exit(scripts.EXIT_SUCCESS)

if __name__ == "__main__":
    main()
