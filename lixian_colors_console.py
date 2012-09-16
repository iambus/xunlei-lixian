
__all__ = ['Console']

import sys

styles = [
	'black',
	'blue',
	'green',
	'red',
	'cyan',
	'yellow',
	'purple',
	'white',

	'bold',
	'italic',
	'underline',
	'inverse',
]


class Console:
	def __init__(self, output=sys.stdout, styles=[]):
		self.output = output
		self.styles = styles
	def __getattr__(self, name):
		if name in styles:
			return self.__class__(self.output, self.styles + [name])
		else:
			raise AttributeError(name)
	def ansi(self, code):
		return self.__class__(self.output, self.styles + [code]) if code not in (None, '') else self
	def __call__(self, s):
		self.write(s)
	def write(self, s):
		self.output.write(s)
	def flush(self, *args):
		self.output.flush(*args)

