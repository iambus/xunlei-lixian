
__all__ = ['init_logger', 'get_logger']

import logging

INFO = logging.INFO
DEBUG = logging.DEBUG
TRACE = 1

def file_logger(path, level):
	import os.path
	path = os.path.expanduser(path)

	logger = logging.getLogger('lixian')
	logger.setLevel(min(level, DEBUG)) # if file log is enabled, always log debug message

	handler = logging.FileHandler(filename=path, )
	handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))

	logger.addHandler(handler)

	return logger

class ConsoleLogger:
	def __init__(self, level=INFO):
		self.level = level
	def stdout(self, message):
		print message
	def info(self, message):
		if self.level <= INFO:
			print message
	def debug(self, message):
		if self.level <= DEBUG:
			print message
	def trace(self, message):
		pass

class FileLogger:
	def __init__(self, path, level=INFO):
		self.level = level
		self.path = path
		self.console = ConsoleLogger(level)
		self.logger = file_logger(path, level)
	def stdout(self, message):
		self.console.stdout(message)
	def info(self, message):
		self.console.info(message)
		self.logger.info(message)
	def debug(self, message):
		self.console.debug(message)
		self.logger.debug(message)
	def trace(self, message):
		self.logger.trace(message)

default_logger = None

def init_logger(use_colors=True, level=INFO, path=None):
	global default_logger
	if not default_logger:
		assert level in (INFO, DEBUG, TRACE)
		if path:
			default_logger = FileLogger(path, level)
		else:
			default_logger = ConsoleLogger(level)

def get_logger():
	init_logger()
	return default_logger

