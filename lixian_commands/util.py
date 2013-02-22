
__all__ = ['parse_login', 'parse_colors', 'parse_size', 'output_tasks', 'usage']

from lixian_cli_parser import *
from lixian_config import get_config
from lixian_config import LIXIAN_DEFAULT_COOKIES
from lixian_encoding import default_encoding
from lixian_colors import colors
from getpass import getpass
import lixian_help

@command_line_value('username', default=get_config('username'))
@command_line_value('password', default=get_config('password'))
@command_line_value('cookies', default=LIXIAN_DEFAULT_COOKIES)
def parse_login(args):
	if args.password == '-':
		args.password = getpass('Password: ')
	if args.cookies == '-':
		args._args['cookies'] = None
	return args

@command_line_option('colors', default=get_config('colors', True))
def parse_colors(args):
	pass

@command_line_option('size', default=get_config('size'))
@command_line_option('format-size', default=get_config('format-size'))
def parse_size(args):
	pass

def output_tasks(tasks, columns, args, top=True):
	for i, t in enumerate(tasks):
		status_colors = {
		'waiting': 'yellow',
		'downloading': 'magenta',
		'completed':'green',
		'pending':'cyan',
		'failed':'red',
		}
		c = status_colors[t['status_text']]
		with colors(args.colors).ansi(c)():
			for k in columns:
				if k == 'n':
					if top:
						print '#%d' % t['#'],
				elif k == 'id':
					print t.get('index', t['id']),
				elif k == 'name':
					print t['name'].encode(default_encoding),
				elif k == 'status':
					with colors(args.colors).bold():
						print t['status_text'],
				elif k == 'size':
					if args.format_size:
						from lixian_util import format_size
						print format_size(t['size']),
					else:
						print t['size'],
				elif k == 'progress':
					print t['progress'],
				elif k == 'speed':
					print t['speed'],
				elif k == 'date':
					print t['date'],
				elif k == 'dcid':
					print t['dcid'],
				elif k == 'gcid':
					print t['gcid'],
				elif k == 'original-url':
					print t['original_url'],
				elif k == 'download-url':
					print t['xunlei_url'],
				else:
					raise NotImplementedError(k)
			print

def to_str(s):
	assert type(s) in (str, unicode)
	return s.encode(default_encoding) if type(s) == unicode else s

def usage(doc=lixian_help.usage, message=None):
	if hasattr(doc, '__call__'):
		doc = doc()
	if message:
		print to_str(message)
	print to_str(doc).strip()
