# stdlib
import os
import io
import contextlib

# internal
from . import errors


@contextlib.contextmanager
def ignored(*exceptions):
    """Allows you to ignore exceptions cleanly using context managers. This
    exists in Python 3.

    """
    try:
        yield
    except exceptions:
        pass


def abspath(fn):
    """Returns the absolute path to `fn`. This will expand ``~`` user home
    abbreviations.

    """
    expanded = os.path.expanduser(fn)
    abspath  = os.path.abspath(expanded)
    return abspath


def ioslice(data, offset=0):
    """Returns a read()-able object which contains `data` starting at `offset`.

    """
    try:
        data.seek(offset)
        return data
    except AttributeError:
        return io.BytesIO(data[offset:])


def bindata(data):
    """Returns a binary, indexed version of `data`.

    If `data` is a read()-able object, it will return the str representation
    of `data`.
    """
    try:
        return data.read()
    except AttributeError:
        return data


def find(db, key, multiple=False):
    """Attempts to find the record in `db` which matches `key`. If the
    lookup of `key` fails, the pwsafe will be searched for a similar entry.

    Returns:
        pass

    Raises:
        .KeyLookupError: If the lookup fails.

    """
    try:
        record  = db[key]
        records = [record]
    except KeyError:
        records = db.search(key)

    if records:
        return records if multiple else records[0]

    error = "The  did not contain an entry for '{}'".format(key)
    raise errors.KeyLookupError(message=error, key=key)

