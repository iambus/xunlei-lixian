#!/usr/bin/env python

from lixian import XunleiClient, encypt_password
from lixian_cli_parser import *
from lixian_tasks import *
from lixian_config import *
import lixian_help
import lixian_hash
import lixian_hash_bt
import lixian_hash_ed2k
import sys
import os
import os.path
import re
from getpass import getpass

from lixian_encoding import default_encoding

def from_native(s):
	return s.decode(default_encoding)

def to_str(s):
	assert type(s) in (str, unicode)
	return s.encode(default_encoding) if type(s) == unicode else s

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

@command_line_parser(help=lixian_help.login)
@with_parser(parse_login)
def login(args):
	if args.cookies == '-':
		args._args['cookies'] = None
	if len(args) < 1:
		args.username = args.username or XunleiClient(cookie_path=args.cookies, login=False).get_username() or get_config('username') or raw_input('ID: ')
		args.password = args.password or get_config('password') or getpass('Password: ')
	elif len(args) == 1:
		args.username = args.username or XunleiClient(cookie_path=args.cookies, login=False).get_username() or get_config('username')
		args.password = args[0]
		if args.password == '-':
			args.password = getpass('Password: ')
	elif len(args) == 2:
		args.username, args.password = list(args)
		if args.password == '-':
			args.password = getpass('Password: ')
	elif len(args) == 3:
		args.username, args.password, args.cookies = list(args)
		if args.password == '-':
			args.password = getpass('Password: ')
	elif len(args) > 3:
		raise RuntimeError('Too many arguments')
	if not args.username:
		raise RuntimeError("What's your name?")
	if args.cookies:
		print 'Saving login session to', args.cookies
	else:
		print 'Testing login without saving session'
	client = XunleiClient(args.username, args.password, args.cookies)

def logout(args):
	args = parse_command_line(args, ['cookies'], default={'cookies': LIXIAN_DEFAULT_COOKIES}, help=lixian_help.logout)
	if len(args):
		raise RuntimeError('Too many arguments')
	print 'logging out from', args.cookies
	assert args.cookies
	client = XunleiClient(cookie_path=args.cookies, login=False)
	client.logout()

def escape_filename(name):
	amp = re.compile(r'&(amp;)+', flags=re.I)
	name = re.sub(amp, '&', name)
	name = re.sub(r'[\\/:*?"<>|]', '-', name)
	return name

def verify_basic_hash(path, task):
	if os.path.getsize(path) != task['size']:
		print 'hash error: incorrect file size'
		return False
	return lixian_hash.verify_dcid(path, task['dcid'])

def verify_hash(path, task):
	if verify_basic_hash(path, task):
		if task['type'] == 'ed2k':
			return lixian_hash_ed2k.verify_ed2k_link(path, task['original_url'])
		else:
			return True

def verify_mini_hash(path, task):
	return os.path.exists(path) and os.path.getsize(path) == task['size'] and lixian_hash.verify_dcid(path, task['dcid'])

def verify_mini_bt_hash(dirname, files):
	for f in files:
		name = f['name'].encode(default_encoding)
		path = os.path.join(dirname, *name.split('\\'))
		if not verify_mini_hash(path, f):
			return False
	return True

def download_single_task(client, download, task, options):
	output = options.get('output')
	output_dir = options.get('output_dir')
	delete = options.get('delete')
	resuming = options.get('resuming')
	overwrite = options.get('overwrite')
	mini_hash = options.get('mini_hash')
	no_hash = options.get('no_hash')
	no_bt_dir = options.get('no_bt_dir')
	save_torrent_file = options.get('save_torrent_file')

	assert client.get_gdriveid()
	if task['status_text'] != 'completed':
		if 'files' not in task:
			print 'skip task %s as the status is %s' % (task['name'].encode(default_encoding), task['status_text'])
			return
	def download1(client, url, path, size):
		if not os.path.exists(path):
			download(client, url, path)
		elif not resuming:
			if overwrite:
				download(client, url, path)
			else:
				raise Exception('%s already exists. Please try --continue or --overwrite' % path)
		else:
			assert os.path.getsize(path) <= size, 'existing file bigger than expected, unsafe to continue nor overwrite'
			if os.path.getsize(path) < size:
				download(client, url, path, resuming)
			elif os.path.getsize(path) == size:
				pass
			else:
				raise NotImplementedError()
	def download2(client, url, path, task):
		size = task['size']
		if mini_hash and resuming and verify_mini_hash(path, task):
			return
		download1(client, url, path, size)
		verify = verify_basic_hash if no_hash else verify_hash
		if not verify(path, task):
			print 'hash error, redownloading...'
			os.remove(path)
			download1(client, url, path, size)
			if not verify(path, task):
				raise Exception('hash check failed')
	download_url = str(task['xunlei_url'])
	if output:
		output_path = output
		output_dir = os.path.dirname(output)
		output_name = os.path.basename(output)
	else:
		output_name = escape_filename(task['name']).encode(default_encoding)
		output_dir = output_dir or '.'
		output_path = os.path.join(output_dir, output_name)
	referer = str(client.get_referer())
	gdriveid = str(client.get_gdriveid())

	if task['type'] == 'bt':
		files, skipped, single_file = expand_bt_sub_tasks(client, task)
		if single_file:
			dirname = output_dir
		else:
			if no_bt_dir:
				output_path = os.path.dirname(output_path)
			dirname = output_path
		assert dirname # dirname must be non-empty, otherwise dirname + os.path.sep + ... might be dangerous
		if dirname and not os.path.exists(dirname):
			os.makedirs(dirname)
			for t in skipped:
				print 'skip task %s/%s (%s) as the status is %s' % (t['id'], t['index'], t['name'].encode(default_encoding), t['status_text'])
		if mini_hash and resuming and verify_mini_bt_hash(dirname, files):
			print task['name'].encode(default_encoding), 'is already done'
			if delete and 'files' not in task:
				client.delete_task(task)
			return
		for f in files:
			name = f['name']
			if f['status_text'] != 'completed':
				print 'Skipped %s file %s ...' % (f['status_text'], name.encode(default_encoding))
				continue
			print 'Downloading', name.encode(default_encoding), '...'
			# XXX: if file name is escaped, hashing bt won't get correct file
			splitted_path = map(escape_filename, name.split('\\'))
			name = os.path.join(*splitted_path).encode(default_encoding)
			path = dirname + os.path.sep + name # fix issue #82
			if splitted_path[:-1]:
				subdir = os.path.join(*splitted_path[:-1]).encode(default_encoding)
				subdir = dirname + os.path.sep + subdir # fix issue #82
				if not os.path.exists(subdir):
					os.makedirs(subdir)
			download_url = str(f['xunlei_url'])
			download2(client, download_url, path, f)
		if save_torrent_file:
			info_hash = str(task['bt_hash'])
			if single_file:
				torrent = os.path.join(dirname, escape_filename(task['name']).encode(default_encoding) + '.torrent')
			else:
				torrent = os.path.join(dirname, info_hash + '.torrent')
			if os.path.exists(torrent):
				pass
			else:
				content = client.get_torrent_file_by_info_hash(info_hash)
				with open(torrent, 'wb') as ouput_stream:
					ouput_stream.write(content)
		if not no_hash:
			torrent_file = client.get_torrent_file(task)
			print 'Hashing bt ...'
			from lixian_progress import SimpleProgressBar
			bar = SimpleProgressBar()
			file_set = [f['name'].encode('utf-8').split('\\') for f in files] if 'files' in task else None
			verified = lixian_hash_bt.verify_bt(output_path, lixian_hash_bt.bdecode(torrent_file)['info'], file_set=file_set, progress_callback=bar.update)
			bar.done()
			if not verified:
				# note that we don't delete bt download folder if hash failed
				raise Exception('bt hash check failed')
	else:
		if output_dir and not os.path.exists(output_dir):
			os.makedirs(output_dir)
		print 'Downloading', output_name, '...'
		download2(client, download_url, output_path, task)

	if delete and 'files' not in task:
		client.delete_task(task)

def download_multiple_tasks(client, download, tasks, options):
	for task in tasks:
		download_single_task(client, download, task, options)
	skipped = filter(lambda t: t['status_text'] != 'completed', tasks)
	if skipped:
		print "Below tasks were skipped as they were not ready:"
		for task in skipped:
			print task['id'], task['status_text'], task['name'].encode(default_encoding)

@command_line_parser(help=lixian_help.download)
@with_parser(parse_login)
@command_line_value('tool', default=get_config('tool', 'wget'))
@command_line_value('input', alias='i')
@command_line_value('output', alias='o')
@command_line_value('output-dir', default=get_config('output-dir'))
@command_line_option('torrent', alias='bt')
@command_line_option('all')
@command_line_value('category')
@command_line_option('delete', default=get_config('delete'))
@command_line_option('continue', alias='c', default=get_config('continue'))
@command_line_option('overwrite')
@command_line_option('mini-hash', default=get_config('mini-hash'))
@command_line_option('hash', default=get_config('hash', True))
@command_line_option('bt-dir', default=True)
@command_line_option('save-torrent-file')
def download_task(args):
	import lixian_download_tools
	download = lixian_download_tools.get_tool(args.tool)
	download_args = {'output':args.output, 'output_dir':args.output_dir, 'delete':args.delete, 'resuming':args._args['continue'], 'overwrite':args.overwrite, 'mini_hash':args.mini_hash, 'no_hash': not args.hash, 'no_bt_dir': not args.bt_dir, 'save_torrent_file':args.save_torrent_file}
	client = XunleiClient(args.username, args.password, args.cookies)
	links = None
	if len(args) or args.input:
		tasks = find_tasks_to_download(client, args)
		if args.output:
			assert len(tasks) == 1
			download_single_task(client, download, tasks[0], download_args)
		else:
			download_multiple_tasks(client, download, tasks, download_args)
	elif args.all:
		tasks = client.read_all_tasks()
		download_multiple_tasks(client, download, tasks, download_args)
	elif args.category:
		tasks = client.read_all_tasks_by_category(from_native(args.category))
		download_multiple_tasks(client, download, tasks, download_args)
	else:
		usage(doc=lixian_help.download, message='Not enough arguments')


@command_line_parser(help=lixian_help.list)
@with_parser(parse_login)
@with_parser(parse_colors)
@with_parser(parse_size)
@command_line_option('all')
@command_line_option('completed')
@command_line_option('deleted')
@command_line_option('expired')
@command_line_value('category')
@command_line_option('id', default=get_config('id', True))
@command_line_option('name', default=True)
@command_line_option('status', default=True)
@command_line_option('dcid')
@command_line_option('gcid')
@command_line_option('original-url')
@command_line_option('download-url')
@command_line_option('speed')
@command_line_option('progress')
@command_line_option('date')
@command_line_option('n', default=get_config('n'))
def list_task(args):
	status = 'all'
	if args.completed:
		status = 'completed'
	elif args.deleted:
		status = 'deleted'
	elif args.expired:
		status = 'expired'

	parent_ids = [a[:-1] for a in args if re.match(r'^#?\d+/$', a)]
	if parent_ids and not all(re.match(r'^#?\d+/$', a) for a in args):
		raise NotImplementedError("Can't mix 'id/' with others")
	assert len(parent_ids) <= 1, "sub-tasks listing only supports single task id"
	ids = [a[:-1] if re.match(r'^#?\d+/$', a) else a for a in args]

	client = XunleiClient(args.username, args.password, args.cookies)
	if parent_ids:
		args[0] = args[0][:-1]
		tasks = search_tasks(client, args, status=status)
		assert len(tasks) == 1
		tasks = client.list_bt(tasks[0])
		#tasks = client.list_bt(client.get_task_by_id(parent_ids[0]))
		tasks.sort(key=lambda x: int(x['index']))
	elif len(ids):
		tasks = search_tasks(client, args, status=status)
	elif args.category:
		tasks = client.read_all_tasks_by_category(from_native(args.category))
	elif status == 'all':
		tasks = client.read_all_tasks()
	elif status == 'completed':
		tasks = filter(lambda x: x['status_text'] == 'completed', client.read_all_tasks()) # by #139
	elif status == 'deleted':
		tasks = client.read_all_deleted()
	elif status == 'expired':
		tasks = client.read_all_expired()
	else:
		raise NotImplementedError(status)
	columns = ['n', 'id', 'name', 'status', 'size', 'progress', 'speed', 'date', 'dcid', 'gcid', 'original-url', 'download-url']
	columns = filter(lambda k: getattr(args, k), columns)

	output_tasks(tasks, columns, args, not parent_ids)

def output_tasks(tasks, columns, args, top=True):
	from lixian_colors import colors
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

@command_line_parser(help=lixian_help.add)
@with_parser(parse_login)
@with_parser(parse_colors)
@with_parser(parse_size)
@command_line_value('input', alias='i')
@command_line_option('torrent', alias='bt')
def add_task(args):
	assert len(args) or args.input
	client = XunleiClient(args.username, args.password, args.cookies)
	links = []
	links.extend(args)
	if args.input:
		import fileinput
		links.extend(line.strip() for line in fileinput.input(args.input) if line.strip())
	if not args.torrent:
		tasks = find_normal_tasks_to_download(client, links)
	else:
		tasks = find_torrent_tasks_to_download(client, links)
	print 'All tasks added. Checking status...'
	columns = ['id', 'status', 'name']
	if args.size:
		columns.append('size')
	output_tasks(tasks, columns, args)

@command_line_parser(help=lixian_help.delete)
@with_parser(parse_login)
@with_parser(parse_colors)
@command_line_option('i')
@command_line_option('all')
def delete_task(args):
	client = XunleiClient(args.username, args.password, args.cookies)
	if len(args):
		to_delete = search_tasks(client, args)
	elif args.all:
		to_delete = client.read_all_tasks()
	if not to_delete:
		print 'Nothing to delete'
		return
	from lixian_colors import colors
	with colors(args.colors).red.bold():
		print "Below files are going to be deleted:"
		for x in to_delete:
			print x['name'].encode(default_encoding)
	if args.i:
		yes_or_no = raw_input('Are your sure to delete below files from Xunlei cloud? ')
		while yes_or_no.lower() not in ('y', 'yes', 'n', 'no'):
			yes_or_no = raw_input('yes or no? ')
		if yes_or_no.lower() in ('y', 'yes'):
			pass
		elif yes_or_no.lower() in ('n', 'no'):
			raise RuntimeError('Deletion abort per user request.')
	client.delete_tasks(to_delete)

@command_line_parser(help=lixian_help.pause)
@with_parser(parse_login)
@with_parser(parse_colors)
@command_line_option('i')
@command_line_option('all')
def pause_task(args):
	client = XunleiClient(args.username, args.password, args.cookies)
	to_pause = search_tasks(client, args)
	print "Below files are going to be paused:"
	for x in to_pause:
		print x['name'].encode(default_encoding)
	client.pause_tasks(to_pause)

@command_line_parser(help=lixian_help.restart)
@with_parser(parse_login)
@with_parser(parse_colors)
@command_line_option('i')
@command_line_option('all')
def restart_task(args):
	client = XunleiClient(args.username, args.password, args.cookies)
	to_restart = search_tasks(client, args)
	print "Below files are going to be restarted:"
	for x in to_restart:
		print x['name'].encode(default_encoding)
	client.restart_tasks(to_restart)

@command_line_parser(help=lixian_help.rename)
@with_parser(parse_login)
def rename_task(args):
	if len(args) != 2 or not re.match(r'\d+$', args[0]):
		usage(lixian_help.rename, 'Incorrect arguments')
		sys.exit(1)
	client = XunleiClient(args.username, args.password, args.cookies)
	taskid, new_name = args
	task = client.get_task_by_id(taskid)
	client.rename_task(task, from_native(new_name))

@command_line_parser(help=lixian_help.readd)
@with_parser(parse_login)
@command_line_option('deleted')
@command_line_option('expired')
@command_line_option('all')
def readd_task(args):
	if args.deleted:
		status = 'deleted'
	elif args.expired:
		status = 'expired'
	else:
		raise NotImplementedError('Please use --expired or --deleted')
	client = XunleiClient(args.username, args.password, args.cookies)
	if status == 'expired' and args.all:
		return client.readd_all_expired_tasks()
	to_readd = search_tasks(client, args, status=status)
	non_bt = []
	bt = []
	if not to_readd:
		return
	print "Below files are going to be re-added:"
	for x in to_readd:
		print x['name'].encode(default_encoding)
		if x['type'] == 'bt':
			bt.append((x['bt_hash'], x['id']))
		else:
			non_bt.append((x['original_url'], x['id']))
	if non_bt:
		urls, ids = zip(*non_bt)
		client.add_batch_tasks(urls, ids)
	for hash, id in bt:
		client.add_torrent_task_by_info_hash2(hash, id)

@command_line_parser(help=lixian_help.info)
@with_parser(parse_login)
@command_line_option('id', alias='i')
def lixian_info(args):
	client = XunleiClient(args.username, args.password, args.cookies, login=False)
	if args.id:
		print client.get_username()
	else:
		print 'id:', client.get_username()
		print 'internalid:', client.get_userid()
		print 'gdriveid:', client.get_gdriveid() or ''

@command_line_parser(help=lixian_help.config)
@command_line_option('print')
@command_line_option('delete')
def lx_config(args):
	if args.delete:
		assert len(args) == 1
		delete_config(args[0])
	elif args['print'] or not len(args):
		if len(args):
			assert len(args) == 1
			print get_config(args[0])
		else:
			print 'Loading', global_config.path, '...\n'
			print source_config()
			print global_config
	else:
		assert len(args) in (1, 2)
		if args[0] == 'password':
			if len(args) == 1 or args[1] == '-':
				password = getpass('Password: ')
			else:
				password = args[1]
			print 'Saving password (encrypted) to', global_config.path
			put_config('password', encypt_password(password))
		else:
			print 'Saving configuration to', global_config.path
			put_config(*args)

def usage(doc=lixian_help.usage, message=None):
	if hasattr(doc, '__call__'):
		doc = doc()
	if message:
		print to_str(message)
	print to_str(doc).strip()

def lx_help(args):
	if len(args) == 1:
		helper = getattr(lixian_help, args[0].lower(), lixian_help.help)
		usage(helper)
	elif len(args) == 0:
		usage(lixian_help.welcome_help)
	else:
		usage(lixian_help.help)

def execute_command(args=sys.argv[1:]):
	if not args:
		usage()
		sys.exit(1)
	command = args[0]
	if command.startswith('-'):
		if command in ('-h', '--help'):
			usage(lixian_help.welcome_help)
		elif command in ('-v', '--version'):
			print '0.0.x'
		else:
			usage()
			sys.exit(1)
		sys.exit(0)
	import lixian_alias
	command = lixian_alias.to_alias(command)
	commands = {'login': login, 'logout': logout, 'download': download_task, 'list': list_task, 'add': add_task, 'delete': delete_task, 'pause': pause_task, 'restart': restart_task, 'rename': rename_task, 'readd': readd_task, 'info': lixian_info, 'config': lx_config, 'help': lx_help}
	import lixian_commands
	commands.update(lixian_commands.commands)
	if command not in commands:
		usage()
		sys.exit(1)
	if '-h' in args or '--help' in args:
		lx_help([command])
	else:
		commands[command](args[1:])

if __name__ == '__main__':
	execute_command()


