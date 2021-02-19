#!/usr/bin/env python3

"""
Functions for dealing with tasks in the uwsgi spooler.
"""

import os
import pwd
import grp
import logging
import struct
import argparse
from collections import OrderedDict

# Type Checking!
from typing import Optional, NamedTuple, Tuple

# Source code is here: https://github.com/unbit/uwsgi/blob/master/core/spooler.c
# shell hack to get the creation time from the spool file name:
#   s=$(echo "${spool_file}" | cut -d'_' -f8);
#   usec=$(echo "${spool}" | cut -d'_' -f9);
#   d=$(date --date="@${s}.${usec}");
#   echo "SPOOL FILE[${spool}]; DATE: [${d}]"

logger = logging.getLogger('uwsgi_spooler_modifier')


class Header(NamedTuple):
    """A uwsgi Protocol Header object.

    The uwsgi protocol is comprised of a 4 byte packet, containing:
        - The first byte is modifier1.
        - The second & third bytes are the 'datasize'.
        - The fourth byte is modifier2.

    For a uWSGI Spooler file modifier1 is 17, the datasize
    is the length of the spooler content (excluding the 'body'),
    and the modifier2 is currently unused / empty.

    Information on the uwsgi protocol can be found here:
    https://uwsgi-docs.readthedocs.io/en/latest/Protocol.html
    """
    modifer1: int
    length: int
    modifer2: int

    @classmethod
    def load(cls, byte_str: bytes) -> 'Header':
        """Serializes a Header() object from a 4 byte byte-string.

        Arguments:
            byte_str (bytes):   A 4 byte protocol/header (i.e. the 1st 4
                                bytes of a uwsgi spooler file.
        Returns:
            header (Header):    A header object that's been unpacked
                                from a byte_str.
        """
        return cls._make(cls.header_format().unpack(byte_str))

    @classmethod
    def header_format(cls) -> struct.Struct:
        """Get struct used for packing & unpacking the header.
        """

        return struct.Struct('<bHb')

    def save(self) -> bytes:
        """Serializes the Header() object back into a byte str.
        """
        return self.header_format().pack(*self)


class Content(OrderedDict):
    """OrderedDict-Like Object that serializes to & from a uwsgi spooler byte string.

    The Content() object can be constructed manually, or it can be `load()`-ed
    from an existing byte string.

    The Content() object can also be serialized back into a uwsgi spooler byte string
    by calling the `save()` function.

    Additionally, the object can calculate it's own length for setting in the uwsgi
    spooler  header (see Header.length), by calling the `get_length()` function.
    """
    SIZE = struct.Struct('<H')

    @classmethod
    def load(cls, byte_str: bytes, full_length: int) -> 'Content':
        """Converts a spooler content byte string into an ordered Dictionary of key,value pairs.

        Takes a byte string [contents of a spooler file, excluding the file header and
        file 'body'] as well as the length of that byte string, and then parses it into a
        dictionary-like object [Content], and then returns that object.

        Arguments:
            byte_str (bytes):   A byte_str read directly from the spooler file
                                containing key, value pairs. This needs to exclude the
                                spooler `body`.
            full_length (int):  The length of the spooler content, as declared in the
                                spooler header.

        Returns:
            Content (dict): An OrderedDict-like object.
        """

        def move_index(index: int, length: int) -> Tuple[bytes, int]:
            """
                Returns a substring of the `byte_str`,
                starting from the index and continuing for length,
                as well as moving the `index` by `length` positions.
            """
            return (byte_str[index: index + length], index + length)

        def get_str(index_position: int) -> Tuple[bytes, int]:
            """
                Returns a parsed string and new index position
            """
            sub, index_position = move_index(index_position, 2)
            length = cls.SIZE.unpack(sub)[0]

            sub, index_position = move_index(index_position, length)
            _str: bytes = struct.unpack(f'{length}s', sub)[0]
            return (_str, index_position)

        result = OrderedDict()
        index_position = 0
        while index_position < full_length:
            key, index_position = get_str(index_position)
            value, index_position = get_str(index_position)

            result[key] = value
        return cls(result)

    def save(self) -> bytes:
        """Serializes the OrderedDict back into a byte str.

            This function will serialize the Content() object back
            into a byte string identical to the ones read directly from the spooler file.

            Returns:
                byte_array (bytes): A byte string in the format of 2x bytes indicating
                                    text size, followed by the text (key), followed by
                                    another 2x bytes for the value size, followed by the
                                    text (value).
        """
        byte_array = b''

        for key, value in self.items():
            byte_array += self.SIZE.pack(len(key))
            byte_array += key if isinstance(key, bytes) else key.encode('utf-8')
            byte_array += self.SIZE.pack(len(value))
            byte_array += value if isinstance(value, bytes) else value.encode('utf-8')

        return byte_array

    def get_length(self) -> int:
        """Calculate the length (number of bytes) of the Content object.
        """
        size = 0
        for key, value in self.items():
            size += len(key) + 2
            size += len(value) + 2
        return size


class Task(object):
    """
        an object representing our task/spooler file.
    """

    @classmethod
    def load(cls, file_name: str) -> 'Task':
        """Loads a uWSGI spooler file from the disk.

        Takes a file path and attempts to load it into our Task() object,
        returning a `Task()` comprised of a `Header()`, `Content()`, and
        a byte_str of the uWSGI spooler `body` content.

        The Structure of the file is:

        file[0]: 17 (if it's a uwsgi spooler file) (modifier1)
        file[1-2]: size of the file in bytes
        file[3]: empty/null/zero (modifier2)
        file[4:[size of the file]]: file content (key, value pairs)
        file[[size of the file]:]: body (extra data just tacked onto the file end).

        Note:
            The spooler files I've been looking at are all little-endian.
        """
        binary_content = b''
        with open(file_name, 'rb') as f:
            binary_content = f.read()

        if len(binary_content) < 4:
            raise Exception('This file is not a uwsgi spooler file')

        header = Header.load(binary_content[:4])
        if header.modifer1 != 17:
            raise Exception('This file is not a uwsgi spooler file')

        content = Content.load(binary_content[4: (header.length + 4)], header.length)

        body_content: Optional[bytes] = None
        if len(binary_content) > (header.length + 4):
            body_content = binary_content[header.length + 4:]

        logger.debug(f'Header: {header}')
        logger.debug(f'Size: {header.length}')
        logger.debug(f'Content: {content}')
        logger.debug(f'Body: {body_content.decode("utf-8")}')

        # Sanity check.
        # Does the header length match our content length?
        if (
                header.length != content.get_length()
        ):
            raise Exception(
                'The file is malformed. \n'
                + 'The size of the file does not match the content length.\n'
                + '[Header Size: {}] != [Content Size: {}]'.format(
                    header.length,
                    content.get_length()
                )
            )
        # Return an instance of the Task class.
        return cls(header, content, body_content)

    # Instance functions
    def __init__(
            self, header: Header, content_dict: Content, body: Optional[bytes] = None
    ) -> None:
        self.header = header
        self.content_dict = content_dict
        self.body = body

    def update(self, key: bytes, value: bytes) -> None:
        """Updates the Tasks's content with a key,value pair.
        """
        # If these aren't bytes then the assumption made by
        # content.get_length() don't work.
        assert(isinstance(key, bytes))
        assert(isinstance(value, bytes))
        # set the value
        self.content_dict[key] = value

    def save(self, file_name: str, owner: Tuple[str, str] = ('root', 'root')) -> None:
        """Writes the task out to a spooler file [should be readable by uwsgi].

        The `save()` takes a filename and an owner tuple (owner, group) and writes the
        task header, content and spooler `body` (if it exists) out to the given file.
        Once the file is created, the save function then attempts to set the owner
        of the file to match the owner tuple provided.

        Arguments:
            file_name (str): A file_name / path to write the spooler task out to.
            owner (tuple):  A tuple of (owner, group) to own the spooler file.
                            Defaults to root.
        """

        self.header = self.header._replace(length=self.content_dict.get_length())
        buffer_str = self.header.save()
        buffer_str += self.content_dict.save()
        if self.body is not None:
            buffer_str += self.body

        # Write
        logger.debug(f'Writing [{buffer_str.decode("utf-8")}] to {file_name}')
        with open(file_name, 'wb') as f:
            f.write(buffer_str)
        # Set owner:
        uid = pwd.getpwnam(owner[0]).pw_uid
        gid = grp.getgrnam(owner[1]).gr_gid
        os.chown(file_name, uid, gid)


def main() -> bool:
    # Parse CLI Arguments.
    parser = get_parser()
    cli_args = parser.parse_args()

    if cli_args.verbose is True:
        logger.setLevel(logging.DEBUG)

    # Load the Spool File.
    task = Task.load(cli_args.filename)
    if not task:
        return False

    # Do any updates requested.
    if cli_args.update:
        for key, value in cli_args.update:
            task.update(key.encode('utf-8'), value.encode('utf-8'))
        logger.debug('Content After Update: \n{}'.format(task.content_dict))

    # Write out a copy of the file, or print the contents.
    if cli_args.update:
        # write it back out with the same owner as it previously had.
        owner = pwd.getpwuid(os.stat(cli_args.filename).st_uid).pw_name
        group = grp.getgrgid(os.stat(cli_args.filename).st_gid).gr_name
        task.save(cli_args.filename + '.update', (owner, group))
        print('Spool File Updated Successfully')
    else:
        print('Spool File Contents: ')
        for key, value in task.content_dict.items():
            print('{}: {}'.format(key, value))
        if task.body is not None:
            print('Body: ')
            print('{}'.format(task.body))
    return True


def get_parser() -> argparse.ArgumentParser:

    def parse_updates(in_str: str) -> Tuple[str, str]:
        if '=' not in in_str:
            raise argparse.ArgumentTypeError('update values must be key=value pairs.')

        return (*in_str.split('=', maxsplit=1), )  # type: ignore

    parser = argparse.ArgumentParser(
        description="Reads & Modifies uWSGI Spooler Files."
    )

    parser.add_argument(
        'filename',
        type=str,
        help='Spooler file to load'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Turn on debug output'
    )

    parser.add_argument(
        '--update',
        type=parse_updates,
        action='append',
        help="key=value pair to update, can be given multiple times."
    )

    return parser


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.WARNING,
        format='[%(asctime)s] - [%(levelname)s]: %(message)s'
    )
    main()
