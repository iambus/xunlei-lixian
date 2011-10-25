#!/usr/bin/env python

def sha1_hash_file(path):
	import hashlib
	h = hashlib.sha1()
	with open(path, 'rb') as stream:
		while True:
			bytes = stream.read(1024*1024)
			if not bytes:
				break
			h.update(bytes)
	return h.hexdigest()

def verify_sha1(path, sha1):
	return sha1_hash_file(path).lower() == sha1.lower()

def dcid_hash_file(path):
	import hashlib
	h = hashlib.sha1()
	size = os.path.getsize(path)
	with open(path, 'rb') as stream:
		if size < 0xF000:
			h.update(stream.read())
		else:
			h.update(stream.read(0x5000))
			stream.seek(size/3)
			h.update(stream.read(0x5000))
			stream.seek(size-0x5000)
			h.update(stream.read(0x5000))
	return h.hexdigest()

def verify_dcid(path, dcid):
	return dcid_hash_file(path).lower() == dcid.lower()

if __name__ == '__main__':
	import sys
	args = sys.argv[1:]
	algorithm = args.pop(0)
	hash_fun = {'--sha1':sha1_hash_file, '--dcid':dcid_hash_file}[algorithm]
	for f in args:
		h = hash_fun(f)
		print '%s *%s' % (h, f)

