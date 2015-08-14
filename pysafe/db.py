# builtin
import os
import collections
import hashlib
import struct
import hmac

# external
import mcrypt

# internal
from . import errors
from . import utils


__builtin_type = type


BLOCK_SIZE = 16   # 16 Byte blocks for Twofish
MODE_CBC = 'cbc'  # Cipher Block Chaining
MODE_ECB = 'ecb'  # Electronic Code Book

TYPE_END = 0xff


class PwSafeV3Field(object):
    """Defines fields and operations for a Password Safe v3 Field

    Attributes:
        type: Fill Out
        value: Fill Out

    """
    HEADER_SIZE = 5  # 4 Bytes (data length) + 1 byte (field type)

    def __init__(self):
        self.type = 0  # field type
        self.value = None  # field value without padding


    @classmethod
    def parse(cls, data, offset=0):
        """Parses `data` at `offset` and returns a PwSafeV3Field instance.

        Args:
            data: A file-like object (``read()``) or an indexed object
                (``list``) containing PwSafeV3Field data.
            offset: The offset of `data` which points to the start of the
                PwSafe v3 Field data.

        Returns:
            An instance of ``PwSafeV3Field``.

        """
        obj = cls()
        dataio = utils.ioslice(data, offset)

        data_len = struct.unpack('<l', dataio.read(4))[0]
        obj.type = ord(dataio.read(1))
        obj.value = dataio.read(data_len)

        return obj

    @property
    def padding(self):
        """Property for field padding.

        Returns:
            Random bytes which can be appended to `self.value` so that
            ``(len(HEADER) + len(PADDING) + len(VALUE)) % BLOCK_SIZE == 0``.

        """
        bufsize = len(self) - len(self.value)
        return os.urandom(bufsize)

    def serialize(self):
        """Returns a binary Password Safe v3 Field.

        Field format: [LENGTH][TYPE][VALUE][PADDING]

        LENGTH : 4 byte LE integer
        TYPE: 1 byte
        VALUE: Variable length string
        PADDING: Random bytes where
                 (len(HEADER) + len(PADDING) + len(VALUE)) % BLOCK_SIZE == 0

        Returns:
            Packed binary form of this Password Safe v3 Field.

        """
        fmt = "<lB%ss" % (len(self))
        data = self.value + self.padding
        return  struct.pack(fmt, (len(self.value), self.type, data))

    def __eq__(self, other):
        """Returns True if `self` and `other` are the same instance or if they
        are both instances of ``PwSafeV3Field`` and have the same ``str()``
        representation (or, ``value`` attribute.

        """
        if self is other:
            return True
        elif self.__class__ is not other.__class__:
            return False
        else:
            return str(self) == str(other)

    def __unicode__(self):
        return unicode(self.value)

    def __str__(self):
        return unicode(self).encode('utf-8')

    def __len__(self):
        """Returns the length of the field, which is a multiple of
        `BLOCK_SIZE`.

        """
        length = PwSafeV3Field.HEADER_SIZE + len(self.value)

        if length < BLOCK_SIZE:
            return BLOCK_SIZE

        q = length / BLOCK_SIZE
        r = length % BLOCK_SIZE

        if r:
            q += 1

        return (BLOCK_SIZE * q)


class PWSafeV3Header(collections.MutableMapping):
    """
                                                      Currently
    Name                        Value        Type    Implemented      Comments
    --------------------------------------------------------------------------
    Version                     0x00        2 bytes       Y              [1]
    UUID                        0x01        UUID          Y              [2]
    Non-default preferences     0x02        Text          Y              [3]
    Tree Display Status         0x03        Text          Y              [4]
    Timestamp of last save      0x04        time_t        Y              [5]
    Who performed last save     0x05        Text          Y   [DEPRECATED 6]
    What performed last save    0x06        Text          Y              [7]
    Last saved by user          0x07        Text          Y              [8]
    Last saved on host          0x08        Text          Y              [9]
    Database Name               0x09        Text          Y              [10]
    Database Description        0x0a        Text          Y              [11]
    Database Filters            0x0b        Text          Y              [12]
    Reserved                    0x0c        -                            [13]
    Reserved                    0x0d        -                            [13]
    Reserved                    0x0e        -                            [13]
    Recently Used Entries       0x0f        Text                         [14]
    Named Password Policies     0x10        Text                         [15]
    Empty Groups                0x11        Text                         [16]
    Reserved                    0x12        Text                         [13]
    End of Entry                0xff        [empty]       Y              [17]

    """
    TYPE_VERSION                    = 0x00
    TYPE_UUID                       = 0x01
    TYPE_NON_DEFAULT_PARAMS         = 0x02
    TYPE_TREE_DISPLAY_STATUS        = 0x03
    TYPE_TIMESTAMP_LAST_SAVE        = 0x04
    TYPE_WHO_LAST_SAVE              = 0x05
    TYPE_WHAT_LAST_SAVE             = 0x06
    TYPE_LAST_SAVE_USER             = 0x07
    TYPE_LAST_SAVE_HOST             = 0x08
    TYPE_DATABASE_NAME              = 0x09
    TYPE_DATABASE_DESC              = 0x0a
    TYPE_DATABASE_FILTERS           = 0x0b
    TYPE_RESERVED_1                 = 0x0c
    TYPE_RESERVED_2                 = 0x0d
    TYPE_RESERVED_3                 = 0x0e
    TYPE_RECENTLY_USED_ENTRIES      = 0x0f
    TYPE_NAMED_PASSWORD_POLICIES    = 0x10
    TYPE_EMPTY_GROUPS               = 0x11
    TYPE_RESERVED_4                 = 0x12
    TYPE_END                        = 0xff

    def __init__(self):
        self.__fields = {}

    @classmethod
    def parse(cls, data, offset=0):
        obj = cls()
        type = None

        while type != TYPE_END:
            field = PwSafeV3Field.parse(data, offset)
            type = field.type
            obj[type] = field
            offset += len(field)

        return obj

    def __setitem__(self, key, value):
        self.__fields[key] = value

    def __getitem__(self, item):
        return self.__fields.get(item)

    def __delitem__(self, key):
        return self.__fields.__delitem__(key)

    def __iter__(self):
        return self.__fields.__iter__()

    def __len__(self):
        return sum(len(v) for v in self.itervalues())

    def __unicode__(self):
        fmt = "%s: %s"
        s = "\n".join(fmt.format(k, str(v)) for k, v in self.iteritems())
        return unicode(s)

    def __str__(self):
        return unicode(self).encode('utf-8')


class PWSafeV3Record(collections.MutableMapping):
    """
    UUID                        0x01        UUID          Y              [1]
    Group                       0x02        Text          Y              [2]
    Title                       0x03        Text          Y
    Username                    0x04        Text          Y
    Notes                       0x05        Text          Y
    Password                    0x06        Text          Y              [3,4]
    Creation Time               0x07        time_t        Y              [5]
    Password Modification Time  0x08        time_t        Y              [5]
    Last Access Time            0x09        time_t        Y              [5,6]
    Password Expiry Time        0x0a        time_t        Y              [5,7]
    *RESERVED*                  0x0b        4 bytes       -              [8]
    Last Modification Time      0x0c        time_t        Y              [5,9]
    URL                         0x0d        Text          Y              [10]
    Autotype                    0x0e        Text          Y              [11]
    Password History            0x0f        Text          Y              [12]
    Password Policy             0x10        Text          Y              [13]
    Password Expiry Interval    0x11        2 bytes       Y              [14]
    Run Command                 0x12        Text          Y
    Double-Click Action         0x13        2 bytes       Y              [15]
    EMail address               0x14        Text          Y              [16]
    Protected Entry             0x15        1 byte        Y              [17]
    Own symbols for password    0x16        Text          Y              [18]
    Shift Double-Click Action   0x17        2 bytes       Y              [15]
    Password Policy Name        0x18        Text          Y              [19]
    End of Entry
    """
    TYPE_TITLE      = 0x03
    TYPE_USERNAME   = 0x04
    TYPE_PASSWORD   = 0x06
    TYPE_GROUP      = 0x02

    def __init__(self):
        self.__fields = {}

    @classmethod
    def parse(cls, data, offset=0):
        record = cls()
        rtype  = None

        while rtype != TYPE_END:
            field = PwSafeV3Field.parse(data, offset)
            record[field.type] = field
            offset += len(field)
            rtype = field.type

        return record

    @property
    def title(self):
        return self.__fields[self.TYPE_TITLE]

    @property
    def group(self):
        return self.__fields[self.TYPE_GROUP]

    @property
    def username(self):
        return self.__fields[self.TYPE_USERNAME]

    @property
    def password(self):
        return self.__fields[self.TYPE_PASSWORD]

    def __setitem__(self, key, value):
        self.__fields[key] = value

    def __getitem__(self, item):
        return self.__fields.get(item)

    def __delitem__(self, key):
        return self.__fields.__delitem__(key)

    def __iter__(self):
        return self.__fields.__iter__()

    def __len__(self):
        return sum(len(f) for f in self.itervalues())

    def __unicode__(self):
        s = "[{}] g: {} u: {} p: {}".format(
            self.title,
            self.group,
            self.username,
            self.password
        )

        return unicode(s)

    def __str__(self):
        return unicode(self).encode('utf=8')



class PWSafeV3PreHeader(object):
    def __init__(self):
        self.tag = None
        self.salt = None
        self.iter = None
        self.hpp = None
        self.b1 = None
        self.b2 = None
        self.b3 = None
        self.b4 = None
        self.iv = None

    @classmethod
    def parse(cls, data):
        obj = cls()
        data = utils.ioslice(data, offset=0)

        obj.tag     = data.read(4)
        obj.salt    = data.read(32)
        obj.iter    = struct.unpack("<l", data.read(4))[0]
        obj.hpp     = data.read(32)
        obj.b1      = data.read(16)
        obj.b2      = data.read(16)
        obj.b3      = data.read(16)
        obj.b4      = data.read(16)
        obj.iv      = data.read(16)

        return obj

    def __len__(self):
        return  (4+32+4+32+(16*4)+16)

    def __unicode__(self):
        return unicode(self.__dict__)

    def __str__(self):
        return unicode(self).encode('utf-8')


class PWSafeDB(object):
    EOF_MARKER =  "PWS3-EOFPWS3-EOF"
    HDR_OFFSET = 152

    def __init__(self):
        self.preheader = None # unencrypted area
        self.header = None
        self.records = []
        self.hmac = None
        self.pp = None # P'
        self.k = None
        self.l = None

    def _check_password(self, pp, db_hpp):
        hpp = hashlib.new("sha256")
        hpp.update(pp)
        hpp = hpp.digest()

        return db_hpp == hpp

    def _stretch_key(self, key, salt, iter_):
        h = hashlib.new("sha256")
        h.update(key)
        h.update(salt)
        digest = h.digest()

        for _ in xrange(iter_):
            tmp_h = hashlib.new("sha256")
            tmp_h.update(digest)
            digest = tmp_h.digest()

        return digest

    def _decrypt(self, data, key, iv=None, mode=MODE_ECB):
        twofish = mcrypt.MCRYPT('twofish', mode)
        twofish.init(key, iv)
        plaintext = twofish.decrypt(data)
        return plaintext

    def _decrypt_data_section(self, data, iv, k):
        ieof = data.rindex(PWSafeDB.EOF_MARKER)
        ciphertext = data[PWSafeDB.HDR_OFFSET:ieof]
        plaintext  = self._decrypt(ciphertext, k, iv, mode=MODE_CBC)

        return plaintext

    def _get_hmac(self, data):
        start = data.rindex(self.EOF_MARKER) + len(self.EOF_MARKER)
        end = start + 32
        hmac_slice = data[start:end]

        return hmac_slice

    def parse(self, db, key):
        """Parses a PWSafe v3 database file."""
        data = utils.ioslice(db, offset=0)
        bindata = utils.bindata(data)

        ph = PWSafeV3PreHeader.parse(bindata)
        pp = self._stretch_key(key, ph.salt, ph.iter)

        if not self._check_password(pp, ph.hpp):
            raise errors.InvalidPasswordError("Incorrect password")

        k = self._decrypt(ph.b1, pp) + self._decrypt(ph.b2, pp) # decrypt data
        l = self._decrypt(ph.b3, pp) + self._decrypt(ph.b4, pp) # used for hmac

        hmac = self._get_hmac(bindata)
        udata = self._decrypt_data_section(bindata, ph.iv, k) # decrypted data section

        header = PWSafeV3Header.parse(udata)
        offset = len(header)

        records = []
        while offset < len(udata):
            record = PWSafeV3Record.parse(udata, offset)
            records.append(record)
            offset += len(record)

        self.preheader = ph
        self.header = header
        self.records = records
        #self.hmac = hmac
        self.pp = pp
        self.k = k
        self.l = l

    def search(self, key):
        records = []
        for record in self.records:
            if key.lower() in str(record.title).lower():
                records.append(record)
        return records

    def groupby(self, key='group'):
        grouped = collections.defaultdict(list)

        for record in self:
            field = getattr(record, key)
            groupkey = str(field)
            grouped[groupkey].append(record)

        return grouped

    def __getitem__(self, item):
        for record in self.records:
            if str(record.title) == item:
                return record

        error = "Unable to find entry for '{0}'".format(item)
        raise KeyError(error)

    def __iter__(self):
        for record in self.records:
            yield record

    def __str__(self):
        s = str(self.preheader) + "\n"
        s = s + str(self.header) + "\n"
        s = s + "\n".join(str(x) for x in self.records)

        return s


def parse(dbfn, dbpw):
    pwsafe = PWSafeDB()

    with open(dbfn, 'rb') as database:
        pwsafe.parse(database, dbpw)

    return pwsafe