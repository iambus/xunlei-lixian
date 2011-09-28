
from lixian import XunleiClient
import sys
import re

def parse_command_line(args, keys=[], bools=[], alias={}, default={}):
	options = {}
	for k in keys:
		options[k] = None
	for k in bools:
		options[k] = None
	left = []
	args = args[:]
	while args:
		x = args.pop(0)
		if x == '--':
			left.extend(args)
			break
		if x.startswith('-'):
			k = x.lstrip('-')
			if k in bools:
				options[k] = True
			elif 'no-'+k in bools:
				options[k] = False
			elif k in keys:
				options[k] = args.pop(0)
			elif k in alias:
				options[alias[k]] = args.pop(0)
			else:
				raise RuntimeError('Unknown option '+x)
		else:
			left.append(x)

	for k in default:
		if options[k] is None:
			options[k] = default[k]

	class Args(object):
		def __init__(self, args, left):
			self._args = args
			self._left = left
			#self.__dict__.update(args)
		def __getattr__(self, k):
			return self._args.get(k, None) or self._args.get(k.replace('_', '-'), None)
		def __getitem__(self, i):
			return self._left[i]
		def __len__(self):
			return len(self._left)
	return Args(options, left)

def usage():
	raise NotImplementedError()

def login(args):
	args = parse_command_line(args, ['cookies'])
	client = XunleiClient(args[0], args[1], args.cookies)

def download(args):
	raise NotImplementedError()

def filter_tasks(tasks, k, v):
	if k == 'name':
		matched = filter(lambda t: t[k].find(v) != -1, tasks)
	else:
		matched = filter(lambda t: t[k] == v, tasks)
	return matched

def search_tasks(client, args, status='all', check=True):
	if status == 'all':
		tasks = client.read_all_tasks()
	elif status == 'completed':
		tasks = client.read_all_tasks()
	else:
		raise NotImplementedError()
	found = []
	for x in args:
		if args.id:
			matched = filter_tasks(tasks, 'id', x)
		elif args.file:
			matched = filter_tasks(tasks, 'name', x)
		elif args.url:
			matched = filter_tasks(tasks, 'original_url', x)
		else:
			if re.match(r'^\d+$', x):
				matched = filter_tasks(tasks, 'id', x)
			else:
				matched = filter_tasks(tasks, 'original_url', x) or filter_tasks(tasks, 'name', x)
		if check:
			if not matched:
				raise RuntimeError('Not task found for '+x)
			if (not args.all) and len(matched) > 1:
				raise RuntimeError('Too tasks found for '+x)
		found.extend(matched)
	return found


def list_task(args):
	args = parse_command_line(args, ['username', 'password', 'cookies'],
	                                ['all', 'completed',
	                                 'task-id', 'name', 'status', 'original-url', 'download-url',
	                                 'id', 'file', 'url',],
									default={'task-id': True, 'name': True, 'status': True})
	client = XunleiClient(args.username, args.password, args.cookies)
	client.set_page_size(100)
	tasks = search_tasks(client, args, status=(args.completed and 'completed' or 'all'), check=False)
	columns = ['task-id', 'name', 'status', 'original-url', 'download-url']
	columns = filter(lambda k: getattr(args, k), columns)
	for t in tasks:
		for k in columns:
			if k == 'task-id':
				print t['id'],
			elif k == 'name':
				print t['name'],
			elif k == 'status':
				print t['status_text'],
			elif k == 'original-url':
				print t['original_url'],
			elif k == 'download-url':
				print t['download_url'],
			else:
				raise NotImplementedError()
		print

def add_task(args):
	args = parse_command_line(args, ['username', 'password', 'cookies'])
	assert len(args)
	client = XunleiClient(args.username, args.password, args.cookies)
	for link in args:
		print 'Adding ' + link
		client.add_task(link)
	tasks = client.read_all_tasks()
	print 'All tasks added. Checking status...'
	for link in args:
		task = filter(lambda t: t['original_url'] == link, tasks)[0]
		print task['status_text'] + ' ' + link

def delete_task(args):
	args = parse_command_line(args, ['username', 'password', 'cookies'], ['id', 'file', 'url', 'i', 'all'])
	client = XunleiClient(args.username, args.password, args.cookies)
	to_delete = search_tasks(client, args)
	print "Below files are going to be deleted:"
	for x in to_delete:
		print x['name']
	if args.i:
		yes_or_no = raw_input('Are your sure to delete below files from Xunlei cloud? ')
		while yes_or_no.lower() not in ('y', 'yes', 'n', 'no'):
			yes_or_no = raw_input('yes or no? ')
		if yes_or_no.lower() in ('y', 'yes'):
			pass
		elif yes_or_no.lower() in ('n', 'no'):
			raise RuntimeError('Deletion abort per user request.')
	client.delete_tasks(to_delete)

def pause_task(args):
	args = parse_command_line(args, ['username', 'password', 'cookies'], ['id', 'file', 'url', 'i', 'all'])
	client = XunleiClient(args.username, args.password, args.cookies)
	to_pause = search_tasks(client, args)
	print "Below files are going to be paused:"
	for x in to_pause:
		print x['name']
	client.pause_tasks(to_pause)

def restart_task(args):
	args = parse_command_line(args, ['username', 'password', 'cookies'], ['id', 'file', 'url', 'i', 'all'])
	client = XunleiClient(args.username, args.password, args.cookies)
	to_restart = search_tasks(client, args)
	print "Below files are going to be restarted:"
	for x in to_restart:
		print x['name']
	client.restart_tasks(to_restart)

def execute_command(args=sys.argv[1:]):
	if not args:
		usage()
		sys.exit(1)
	command = args[0]
	if command.startswith('-'):
		if command in ('-h', '--help'):
			usage()
		elif command in ('-v', '--version'):
			print '0.0.x'
		else:
			usage()
			sys.exit(1)
		sys.exit(0)
	commands = {'login': login, 'download': download, 'list': list_task, 'add': add_task, 'delete': delete_task, 'pause': pause_task, 'restart': restart_task}
	if command not in commands:
		usage()
		sys.exit(1)
	commands[command](args[1:])

#x = execute_command(['delete', '-i', '--cookies', 'xunlei.cookies', 'ed2k://|file|%5BSC-OL%5D%5BKaiji2%5D%5B01%5D%5BMKV%5D%5BX264_AAC%5D%5B1280X720%5D%5B6C77C65F%5D.gb.ass|56114|e39a590424b6bb0574c40989d199c91c|h=er4uegovpq3p2jjz7pejtqx242j5ioym|/'])
#x = execute_command(['restart', '-i', '--cookies', 'xunlei.cookies', '--file', '--all', 'zip'])

