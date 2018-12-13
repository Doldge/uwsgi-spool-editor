#!/usr/bin/env python3

"""
Functions for dealing with tasks in the uwsgi spooler.
"""

import sys
import os
import pwd
import grp
import logging
from collections import OrderedDict

logging.basicConfig(
	level=logging.INFO,
	format='[%(asctime)s] - [%(levelname)s]: %(message)s'
)
logger = logging.getLogger('uwsgi_spooler_modifier')


class Task(object):
	"""
		an object representing our task/spooler file.
	"""
	@staticmethod
	def calculate_content_length(content_list):
		# length of the content
		# = number of bytes required to represent the size of the item.
		#   (so any item with a length < 256 should be 1 byte)
		#  + 1 NULL byte (\x00)
		#  + number of bytes required to represent the item.
		content_size = [
			# because we need to convert the bit_length to a byte_length.
			((len(x).bit_length() + 7) // 8) +
			# NULL byte
			1 +
			# length of the item.
			len(x)
			for x in content_list
		]
		return sum(content_size)

	@classmethod
	def init_from_file(cls, file_name):
		binary_content = b''
		with open(file_name, 'rb') as f:
			binary_content = f.read()

		content_list = binary_content.partition(b'\x00')

		# Structure of the file header is:
		# file_header[0] == 17 (if it's a uwsgi spooler file)
		# file_header[1-n] == size of the file in bytes
		# file_header[n+1] == null byte (that we split on, so not actually in the
		# file_header object).
		# These two values are excluded from our size.
		file_header = content_list[0]
		if (int(file_header[0]) != 17):
			# This is not a uwsgi spooler file.
			raise Exception('This file is not a uwsgi spooler file')
		# convert size to an int;
		# the spooler files I've been looking at are all little-endian.
		file_size = int.from_bytes(file_header[1:], byteorder='little')

		# This is a string of length|null|key|length|null|value|... sets.
		# This block converts the contents of the file into a list.
		bytes_list = list(content_list[2])
		content_list = []
		str_length = 0
		buffered_bytes = b''
		for b in bytes_list:
			b_byte = b.to_bytes(1, byteorder='little')
			if b_byte != b'\x00' and not str_length:
				# set up the length of the string
				buffered_bytes += b_byte
			elif b != b'\x00' and str_length:
				# we're dealing with a key or value
				buffered_bytes += b_byte
				str_length -= 1
				if not str_length:
					# We've got all of the key/value; add it to the list and
					# then flush the buffer.
					content_list.append(buffered_bytes)
					buffered_bytes = b''
			elif b_byte == b'\x00':
				# we've hit the null byte, setup the string length and then flush
				# the buffer.
				str_length = int.from_bytes(buffered_bytes, byteorder='little')
				buffered_bytes = b''

		# convert our list into key-value pairs.
		file_contents = OrderedDict()
		for i, item in enumerate(content_list):
			if i % 2 == 0:
				file_contents[item] = None
			elif i % 2 == 1:
				file_contents[content_list[i - 1]] = item

		content_length = Task.calculate_content_length(content_list)

		# Sanity check.
		# Does the header length match our content length?
		if (
			file_size != content_length
		):
			raise Exception(
				'The file is malformed. \n' +
				'The size of the file does not match the content length.\n' +
				'[Header Size: {}] != [Content Size: {}]'.format(
					file_size,
					content_length
				)
			)
		logger.debug(
			(
				file_size,
				file_contents,
				content_length
			)
		)
		# Return an instance of the Task class.
		return cls(file_contents, file_size)

	# Instance functions
	def __init__(self, content_dict, file_size):
		self.content_dict = content_dict
		self.file_size = file_size

	def update(self, key, value):
		# Make sure we've got bytes objects
		if not isinstance(key, bytes):
			key = key.encode('utf8')
		if not isinstance(value, bytes):
			if not isinstance(value, str):
				value = str(value)
			value = value.encode('utf8')

		# Will raise an exception if key doesn't exist.
		self.content_dict[key]
		# set the value
		self.content_dict[key] = value
		content_list = []
		for x, y in self.content_dict.items():
			content_list.append(x)
			content_list.append(y)
		self.file_size = Task.calculate_content_length(content_list)
		return value

	def write_to_file(self, file_name, owner=('root', 'root')):
		# initialize the buffer to our uwsgi spooler byte.
		buffer_str = b'\x11'
		# we need to then append the length of the content to the buffer
		# Sanity check the length before appending
		content_list = []
		for key, value in self.content_dict.items():
			content_list.append(key)
			content_list.append(value)
		expected_size = Task.calculate_content_length(content_list)
		if expected_size != self.file_size:
			raise Exception(
				"sizes don't match; Somethings gone wrong!" +
				"[{}] != [{}]".format(expected_size, self.file_size)
			)
		# Add the size
		buffer_str += self.file_size.to_bytes(
			((self.file_size.bit_length() + 7) // 8),
			byteorder='little'
		)
		# Add the null byte;
		buffer_str += b'\x00'
		# iterate through our dictionary, for each key=value write them to the
		# buffer.
		for key, value in self.content_dict.items():
			# key size
			buffer_str += len(key).to_bytes(
				((len(key).bit_length() + 7) // 8),
				byteorder='little'
			)
			# Null Byte
			buffer_str += b'\x00'
			# key
			buffer_str += key
			# value size
			buffer_str += len(value).to_bytes(
				((len(value).bit_length() + 7) // 8),
				byteorder='little'
			)
			# Null byte
			buffer_str += b'\x00'
			# value
			buffer_str += value

		# Write
		logger.debug('Writing [{}] to {}'.format(buffer_str, file_name))
		with open(file_name, 'wb') as f:
			f.write(buffer_str)
		# Set owner:
		uid = pwd.getpwnam(owner[0]).pw_uid
		gid = grp.getgrnam(owner[1]).gr_gid
		os.chown(file_name, uid, gid)
		return


def main(argv):
	file_name = None
	updates = {}
	for i, arg in enumerate(argv):
		if arg == '--filename':
			file_name = argv[i + 1]
		elif arg == '--update':
			update_item = argv[i + 1]
			if '=' not in update_item:
				raise Exception('update must be key=value')
			update_item = update_item.split('=')
			updates[update_item[0].strip()] = update_item[1].strip()
		elif arg == '-v' or arg == '--verbose':
			logger.setLevel(logging.DEBUG)
		elif arg == '-h' or arg == '--help':
			usage()
			return False
		continue

	if not file_name:
		raise Exception("No filename specified")
	if not os.path.exists(file_name):
		raise Exception('{} does not exist'.format(file_name))

	res = Task.init_from_file(file_name)
	if not res:
		return False
	if updates:
		for key, value in updates.items():
			res.update(key, value)
	logger.debug('Content After Update: \n{}'.format(res.content_dict))

	if updates:
		# write it back out with the same owner as it previously had.
		owner = pwd.getpwuid(os.stat(file_name).st_uid).pw_name
		group = grp.getgrgid(os.stat(file_name).st_gid).gr_name
		res.write_to_file(file_name + '.update', (owner, group))
	else:
		for key, value in res.content_dict.items():
			print('{}: {}'.format(key, value))
	return True


def usage(error_str=None):
	print(
		'''
	--filename [filename]
		The path/name of the spooler file to edit.
	--update key=value
		The key/value pair in the spooler file to change. This key can be
		passed multiple times in order to update multiple values.
	-v | --verbose
		Turn on DEBUG output.
	-h | --help
		Print this help text.

	If 'update' values aren't passed, then the script will just print the
	key=value pairs for the file and exit.
	If it is passed, it creates a file with the same name as the original but
	with '.update' at the end.
		'''
	)


if __name__ == '__main__':
	main(sys.argv)
