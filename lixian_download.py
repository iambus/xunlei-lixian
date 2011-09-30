
import asyncore
import asynchat
import socket
import re
from cStringIO import StringIO
from time import time

#asynchat.async_chat.ac_out_buffer_size = 1024*1024

class http_client(asynchat.async_chat):

	def __init__(self, url, headers=None):
		asynchat.async_chat.__init__(self)

		host, port, path = re.match(r'http://([^/]+)(?:(\d+))?(/.*)?$', url).groups()
		port = int(port or 80)
		path = path or '/'
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connect((host, port))

		self.user_headers = headers
		request_headers = {'host': host, 'connection': 'close'}
		if headers:
			request_headers.update(headers)
		headers = request_headers
		self.request = 'GET %s HTTP/1.1\r\n%s\r\n\r\n' % (path, '\r\n'.join('%s: %s' % (k, headers[k]) for k in headers))
		self.op = 'GET'

		self.headers = {} # for response headers

		self.buffer = StringIO()
		self.cache_size = 0
		self.size = None
		self.completed = 0
		self.set_terminator("\r\n\r\n")
		self.reading_headers = True

	def handle_connect(self):
		self.start_time = time()
		self.push(self.request)

	def handle_close(self):
		asynchat.async_chat.handle_close(self)
		self.handle_status_update(self.size, self.completed, force_update=True)
		self.handle_speed_update(self.completed, self.start_time, force_update=True)

	def handle_error(self):
		self.close()
		raise
		#asynchat.async_chat.handle_error(self)

	def collect_incoming_data(self, data):
		if self.reading_headers:
			self.buffer.write(data)
			return
		elif self.cache_size:
			self.buffer.write(data)
			if self.buffer.tell() > self.cache_size:
				self.handle_data(self.buffer.getvalue())
				self.buffer.truncate(0)
		else:
			self.handle_data(data)

		self.completed += len(data)
		self.handle_status_update(self.size, self.completed)
		self.handle_speed_update(self.completed, self.start_time)

	def handle_data(self, data):
		print len(data)
		pass

	def parse_headers(self, header):
		lines = header.split('\r\n')
		status_line = lines.pop(0)
		#print status_line
		protocal, status_code, status_text = re.match(r'^HTTP/([\d.]+) (\d+) (.+)$', status_line).groups()
		status_code = int(status_code)
		self.status_code = status_code
		self.status_text = status_text
		#headers = dict(h.split(': ', 1) for h in lines)
		for k, v in (h.split(': ', 1) for h in lines):
			self.headers[k.lower()] = v

		if status_code == 200:
			pass
		elif status_code == 302:
			return self.handle_http_relocate(self.headers['location'])
		else:
			return self.handle_http_status_error()

		self.size = self.headers.get('content-length', None)
		if self.size is not None:
			self.size = int(self.size)
		self.handle_http_headers()

	def found_terminator(self):
		if self.reading_headers:
			self.reading_headers = False
			self.parse_headers("".join(self.buffer.getvalue()))
			self.buffer.truncate(0)
			self.set_terminator(None)
		else:
			raise NotImplementedError()

	def handle_http_headers(self):
		pass

	def handle_http_status_error(self):
		self.close()

	def handle_http_relocate(self, location):
		self.close()
		relocate_times = getattr(self, 'relocate_times', 0)
		max_relocate_times = getattr(self, 'max_relocate_times', 1)
		if relocate_times >= max_relocate_times:
			raise Exception('too many relocate times')
		new_client = self.__class__(location, headers=self.user_headers)
		new_client.relocate_times = relocate_times + 1
		new_client.max_relocate_times = max_relocate_times

	def handle_status_update(self, total, completed, force_update=False):
		pass

	def handle_speed_update(self, completed, start_time, force_update=False):
		pass


def download(url, path, headers=None):
	class download_client(http_client):
		def __init__(self, url, headers=headers):
			http_client.__init__(self, url, headers=headers)
			self.last_status_time = time()
			self.last_speed_time = time()
			self.last_size = 0
			self.path = path
			self.output = None
		def handle_connect(self):
			http_client.handle_connect(self)
		def handle_close(self):
			http_client.handle_close(self)
			if self.output:
				self.output.close()
				self.output = None
		def handle_http_status_error(self):
			http_client.handle_http_status_error(self)
			print 'http status error:', self.status_code, self.status_text
		def handle_data(self, data):
			if not self.output:
				self.output = open(path, 'wb')
			self.output.write(data)
		def handle_status_update(self, total, completed, force_update=False):
			if total is None:
				return
			if time() - self.last_status_time > 1 or force_update:
				print '%.02f' % (completed*100.0/total)
				self.last_status_time = time()
		def handle_speed_update(self, completed, start_time, force_update=False):
			now = time()
			period = now - self.last_speed_time
			if period > 1 or force_update:
				print '%.02f, %.02f' % ((completed-self.last_size)/period, completed/(now-start_time))
				self.last_speed_time = time()
				self.last_size = completed
		def __del__(self): # XXX: sometimes handle_close() is not called, don't know why...
			#http_client.__del__(self)
			if self.output:
				self.output.close()
				self.output = None
	client = download_client(url)
	asyncore.loop()



