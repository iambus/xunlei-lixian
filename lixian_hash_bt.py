
import os.path
import sys
import hashlib
from cStringIO import StringIO

default_encoding = sys.getfilesystemencoding()
if default_encoding is None or default_encoding.lower() == 'ascii':
	default_encoding = 'utf-8'

class decoder:
	def __init__(self, bytes):
		self.bytes = bytes
		self.i = 0
	def decode_value(self):
		x = self.bytes[self.i]
		if x.isdigit():
			return self.decode_string()
		self.i += 1
		if x == 'd':
			v = {}
			while self.peek() != 'e':
				k = self.decode_string()
				v[k] = self.decode_value()
			self.i += 1
			return v
		elif x == 'l':
			v = []
			while self.peek() != 'e':
				v.append(self.decode_value())
			self.i += 1
			return v
		elif x == 'i':
			return self.decode_int()
		else:
			raise NotImplementedError(x)
	def decode_string(self):
		i = self.bytes.index(':', self.i)
		n = int(self.bytes[self.i:i])
		s = self.bytes[i+1:i+1+n]
		self.i = i + 1 + n
		return s
	def decode_int(self):
		e = self.bytes.index('e', self.i)
		n = int(self.bytes[self.i:e])
		self.i = e + 1
		return n
	def peek(self):
		return self.bytes[self.i]

class encoder:
	def __init__(self, stream):
		self.stream = stream
	def encode(self, v):
		if type(v) == str:
			self.stream.write(str(len(v)))
			self.stream.write(':')
			self.stream.write(v)
		elif type(v) == dict:
			self.stream.write('d')
			for k in sorted(v):
				self.encode(k)
				self.encode(v[k])
			self.stream.write('e')
		elif type(v) == list:
			self.stream.write('l')
			for x in v:
				self.encode(x)
			self.stream.write('e')
		elif type(v) == int:
			self.stream.write('i')
			self.stream.write(str(v))
			self.stream.write('e')
		else:
			raise NotImplementedError(type(v))

def bdecode(bytes):
	return decoder(bytes).decode_value()

def bencode(v):
	from cStringIO import StringIO
	stream = StringIO()
	encoder(stream).encode(v)
	return stream.getvalue()

def info_hash(path):
	with open(path, 'rb') as stream:
		return hashlib.sha1(bencode(bdecode(stream.read())['info'])).hexdigest()

def encode_path(path):
	return path.decode('utf-8').encode(default_encoding)

class sha1_reader:
	def __init__(self, pieces, progress_callback=None):
		assert pieces
		assert len(pieces) % 20 == 0
		self.total = len(pieces)/20
		self.processed = 0
		self.stream = StringIO(pieces)
		self.progress_callback = progress_callback
	def next_sha1(self):
		self.processed += 1
		if self.progress_callback:
			self.progress_callback(float(self.processed)/self.total)
		return self.stream.read(20)

def verify_bt_single_file(path, info, progress_callback=None):
	# TODO: check md5sum if available
	if os.path.getsize(path) != info['length']:
		return False
	piece_length = info['piece length']
	assert piece_length <= 1024*1024
	sha1_stream = sha1_reader(info['pieces'], progress_callback=progress_callback)
	with open(path, 'rb') as stream:
		while True:
			bytes = stream.read(piece_length)
			sha1 = sha1_stream.next_sha1()
			if bytes:
				assert len(sha1) == 20
				if hashlib.sha1(bytes).digest() != sha1:
					return False
			else:
				assert len(sha1) == 0
				break
	assert sha1_stream.next_sha1() == ''
	return True

def verify_bt_multiple(folder, info, progress_callback=None):
	# TODO: check md5sum if available
	piece_length = info['piece length']
	assert piece_length <= 1024*1024
	files = [{'path':os.path.join(folder, apply(os.path.join, x['path'])), 'length':x['length']} for x in info['files']]

	sha1_stream = sha1_reader(info['pieces'], progress_callback=progress_callback)
	sha1sum = hashlib.sha1()

	piece_left = piece_length
	complete_piece = True

	while files:
		f = files.pop(0)
		path = f['path']
		size = f['length']
		if os.path.exists(path):
			if os.path.getsize(path) != size:
				return False
			if size <= piece_left:
				with open(path, 'rb') as stream:
					bytes = stream.read()
				assert len(bytes) == size
				sha1sum.update(bytes)
				piece_left -= size
				if not piece_left:
					if complete_piece and sha1sum.digest() != sha1_stream.next_sha1():
						return False
					complete_piece = True
					sha1sum = hashlib.sha1()
					piece_left = piece_length
			else:
				with open(path, 'rb') as stream:
					while size >= piece_left:
						bytes = stream.read(piece_left)
						assert len(bytes) == piece_left
						size -= piece_left
						sha1sum.update(bytes)
						if sha1sum.digest() != sha1_stream.next_sha1():
							return False
						sha1sum = hashlib.sha1()
						piece_left = piece_length
					if size:
						bytes = stream.read(size)
						assert len(bytes) == size
						sha1sum.update(bytes)
		else:
			while size >= piece_left:
				size -= piece_left
				sha1_stream.next_sha1()
				sha1sum = hashlib.sha1()
				piece_left = piece_length
			if size:
				complete_piece = False
				piece_left -= size
			else:
				complete_piece = True

	if piece_left < piece_length:
		if complete_piece:
			if sha1sum.digest() != sha1_stream.next_sha1():
				return False
		else:
			sha1_stream.next_sha1()
	assert sha1_stream.next_sha1() == ''

	return True

def verify_bt(path, info, progress_callback=None):
	if not os.path.exists(path):
		raise Exception("File doesn't exist: %s" % path)
	if 'files' not in info:
		if os.path.isfile(path):
			return verify_bt_single_file(path, info, progress_callback=progress_callback)
		else:
			path = os.path.join(path, encode_path(info['name']))
			return verify_bt_single_file(path, info, progress_callback=progress_callback)
	else:
		return verify_bt_multiple(path, info, progress_callback=progress_callback)

def verify_bt_file(path, torrent_path, progress_callback=None):
	with open(torrent_path, 'rb') as x:
		return verify_bt(path, bdecode(x.read())['info'], progress_callback)


