#!/usr/bin/env python

from lixian import XunleiClient, encypt_password
from lixian_cli_parser import parse_command_line
from lixian_tasks import *
from lixian_config import *
import lixian_help
import lixian_hash
import lixian_hash_bt
import lixian_hash_ed2k
import subprocess
import sys
import os
import os.path
import re
import urllib2
from getpass import getpass

from lixian_encoding import default_encoding

def from_native(s):
	return s.decode(default_encoding)

def to_utf_8(url):
	try:
		return url.decode(default_encoding).encode('utf-8')
	except:
		return url

def to_str(s):
	assert type(s) in (str, unicode)
	return s.encode(default_encoding) if type(s) == unicode else s

def parse_login_command_line(args, keys=[], bools=[], alias={}, default={}, help=None):
	common_keys = ['username', 'password', 'cookies']
	common_default = {'cookies': LIXIAN_DEFAULT_COOKIES, 'username': get_config('username'), 'password': get_config('password')}
	common_keys.extend(keys)
	common_default.update(default)
	args = parse_command_line(args, common_keys, bools, alias, common_default, help=help)
	if args.password == '-':
		args.password = getpass('Password: ')
	if args.cookies == '-':
		args._args['cookies'] = None
	return args

def login(args):
	args = parse_login_command_line(args, help=lixian_help.login)
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

def urllib2_download(client, download_url, filename, resuming=False):
	'''In the case you don't even have wget...'''
	assert not resuming
	print 'Downloading', download_url, 'to', filename, '...'
	request = urllib2.Request(download_url, headers={'Cookie': 'gdriveid='+client.get_gdriveid()})
	response = urllib2.urlopen(request)
	import shutil
	with open(filename, 'wb') as output:
		shutil.copyfileobj(response, output)

def asyn_download(client, download_url, filename, resuming=False):
	import lixian_download
	lixian_download.download(download_url, filename, headers={'Cookie': 'gdriveid='+str(client.get_gdriveid())}, resuming=resuming)

def wget_download(client, download_url, filename, resuming=False):
	gdriveid = str(client.get_gdriveid())
	wget_opts = ['wget', '--header=Cookie: gdriveid='+gdriveid, download_url, '-O', filename]
	if resuming:
		wget_opts.append('-c')
	wget_opts.extend(get_config('wget-opts', '').split())
	exit_code = subprocess.call(wget_opts)
	if exit_code != 0:
		raise Exception('wget exited abnormaly')

def curl_download(client, download_url, filename, resuming=False):
	gdriveid = str(client.get_gdriveid())
	curl_opts = ['curl', '-L', download_url, '--cookie', 'gdriveid='+gdriveid, '--output', filename]
	if resuming:
		curl_opts += ['--continue-at', '-']
	curl_opts.extend(get_config('curl-opts', '').split())
	exit_code = subprocess.call(curl_opts)
	if exit_code != 0:
		raise Exception('curl exited abnormaly')

def aria2_download(client, download_url, path, resuming=False):
	gdriveid = str(client.get_gdriveid())
	dir = os.path.dirname(path)
	filename = os.path.basename(path)
	aria2_opts = ['aria2c', '--header=Cookie: gdriveid='+gdriveid, download_url, '--out', filename, '--file-allocation=none']
	if dir:
		aria2_opts.extend(('--dir', dir))
	if resuming:
		aria2_opts.append('-c')
	aria2_opts.extend(get_config('aria2-opts', '').split())
	exit_code = subprocess.call(aria2_opts)
	if exit_code != 0:
		raise Exception('aria2c exited abnormaly')

def axel_download(client, download_url, path, resuming=False):
	gdriveid = str(client.get_gdriveid())
	axel_opts = ['axel', '--header=Cookie: gdriveid='+gdriveid, download_url, '--output', path]
	axel_opts.extend(get_config('axel-opts', '').split())
	exit_code = subprocess.call(axel_opts)
	if exit_code != 0:
		raise Exception('axel exited abnormaly')

# TODO: support axel, ProZilla

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
		files = client.list_bt(task)
		if len(files) == 1 and files[0]['name'] == task['name']:
			dirname = output_dir
		else:
			dirname = output_path
		assert dirname # dirname must be non-empty, otherwise dirname + os.path.sep + ... might be dangerous
		if dirname and not os.path.exists(dirname):
			os.makedirs(dirname)
		if 'files' in task:
			ordered_files = []
			indexed_files = dict((f['index'], f) for f in files)
			subs = []
			for index in task['files']:
				if index.startswith('.'):
					subs.extend([x['index'] for x in files if x['name'].lower().endswith(index.lower())])
				else:
					subs.append(int(index))
			for index in subs:
				t = indexed_files[index]
				if t not in ordered_files:
					if t['status_text'] != 'completed':
						print 'skip task %s/%s (%s) as the status is %s' % (t['id'], index, t['name'].encode(default_encoding), t['status_text'])
					else:
						ordered_files.append(t)
			files = ordered_files
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

def download_task(args):
	args = parse_login_command_line(args,
	                                ['tool', 'output', 'output-dir', 'input'],
	                                ['delete', 'continue', 'overwrite', 'torrent', 'all', 'mini-hash', 'hash'],
									alias={'o': 'output', 'i': 'input', 'c':'continue', 'bt':'torrent'},
									default={'tool':get_config('tool', 'wget'),'delete':get_config('delete'),'continue':get_config('continue'),'output-dir':get_config('output-dir'), 'mini-hash':get_config('mini-hash'), 'hash':get_config('hash', True)},
	                                help=lixian_help.download)
	download = {'wget':wget_download, 'curl': curl_download, 'aria2':aria2_download, 'aria2c':aria2_download, 'axel':axel_download, 'asyn':asyn_download, 'urllib2':urllib2_download}[args.tool]
	download_args = {'output':args.output, 'output_dir':args.output_dir, 'delete':args.delete, 'resuming':args._args['continue'], 'overwrite':args.overwrite, 'mini_hash':args.mini_hash, 'no_hash': not args.hash}
	client = XunleiClient(args.username, args.password, args.cookies)
	links = None
	if len(args) or args.input:
		assert not args.output
		tasks = find_tasks_to_download(client, args)
		if args.output:
			assert len(tasks) == 1
			download_single_task(client, download, tasks[0], download_args)
		else:
			download_multiple_tasks(client, download, tasks, download_args)
	elif args.all:
		#tasks = client.read_all_completed()
		tasks = client.read_all_tasks()
		download_multiple_tasks(client, download, tasks, download_args)
	else:
		usage(doc=lixian_help.download, message='Not enough arguments')


def list_task(args):
	args = parse_login_command_line(args, [],
	                                ['all', 'completed',
	                                 'id', 'name', 'status', 'size', 'dcid', 'gcid', 'original-url', 'download-url', 'speed', 'progress', 'date',
	                                 'n'],
									default={'id': True, 'name': True, 'status': True, 'n': get_config('n')},
									help=lixian_help.list)

	parent_ids = [a[:-1] for a in args if re.match(r'^#?\d+/$', a)]
	if parent_ids and not all(re.match(r'^#?\d+/$', a) for a in args):
		raise NotImplementedError("Can't mix 'id/' with others")
	assert len(parent_ids) <= 1, "sub-tasks listing only supports single task id"
	ids = [a[:-1] if re.match(r'^#?\d+/$', a) else a for a in args]

	client = XunleiClient(args.username, args.password, args.cookies)
	if parent_ids:
		args[0] = args[0][:-1]
		tasks = search_tasks(client, args, status=(args.completed and 'completed' or 'all'))
		assert len(tasks) == 1
		tasks = client.list_bt(tasks[0])
		#tasks = client.list_bt(client.get_task_by_id(parent_ids[0]))
		tasks.sort(key=lambda x: int(x['index']))
	elif len(ids):
		tasks = search_tasks(client, args, status=(args.completed and 'completed' or 'all'))
	elif args.completed:
		tasks = client.read_all_completed()
	else:
		tasks = client.read_all_tasks()
	columns = ['n', 'id', 'name', 'status', 'size', 'progress', 'speed', 'date', 'dcid', 'gcid', 'original-url', 'download-url']
	columns = filter(lambda k: getattr(args, k), columns)
	for i, t in enumerate(tasks):
		for k in columns:
			if k == 'n':
				if not parent_ids:
					print '#%d' % t['#'],
			elif k == 'id':
				print t.get('index', t['id']),
			elif k == 'name':
				print t['name'].encode(default_encoding),
			elif k == 'status':
				print t['status_text'],
			elif k == 'size':
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

def add_task(args):
	args = parse_login_command_line(args, ['input'], ['torrent'], alias={'i':'input','bt':'torrent'}, help=lixian_help.add)
	assert len(args) or args.input
	client = XunleiClient(args.username, args.password, args.cookies)
	links = []
	links.extend(args)
	if args.input:
		with open(args.input) as x:
			links.extend(line.strip() for line in x.readlines() if line.strip())
	if not args.torrent:
		tasks = find_normal_tasks_to_download(client, links)
	else:
		tasks = find_torrent_tasks_to_download(client, links)
	print 'All tasks added. Checking status...'
	for t in tasks:
		print t['id'], t['status_text'], t['name']

def delete_task(args):
	args = parse_login_command_line(args, [], ['i', 'all'], help=lixian_help.delete)
	client = XunleiClient(args.username, args.password, args.cookies)
	to_delete = search_tasks(client, args)
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

def pause_task(args):
	args = parse_login_command_line(args, [], ['i', 'all'], help=lixian_help.pause)
	client = XunleiClient(args.username, args.password, args.cookies)
	to_pause = search_tasks(client, args)
	print "Below files are going to be paused:"
	for x in to_pause:
		print x['name'].encode(default_encoding)
	client.pause_tasks(to_pause)

def restart_task(args):
	args = parse_login_command_line(args, [], ['i', 'all'], help=lixian_help.restart)
	client = XunleiClient(args.username, args.password, args.cookies)
	to_restart = search_tasks(client, args)
	print "Below files are going to be restarted:"
	for x in to_restart:
		print x['name'].encode(default_encoding)
	client.restart_tasks(to_restart)

def rename_task(args):
	args = parse_login_command_line(args, [], [], help=lixian_help.rename)
	if len(args) != 2 or not re.match(r'\d+$', args[0]):
		usage(lixian_help.rename, 'Incorrect arguments')
		sys.exit(1)
	client = XunleiClient(args.username, args.password, args.cookies)
	taskid, new_name = args
	task = client.get_task_by_id(taskid)
	client.rename_task(task, from_native(new_name))

def lixian_info(args):
	args = parse_login_command_line(args, help=lixian_help.info)
	client = XunleiClient(args.username, args.password, args.cookies, login=False)
	print 'id:', client.get_username()
	print 'internalid:', client.get_userid()
	print 'gdriveid:', client.get_gdriveid() or ''

def lx_config(args):
	args = parse_command_line(args, [], ['print', 'delete'], help=lixian_help.config)
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

def lx_diagnostics(args):
	import lixian_diagnostics
	lixian_diagnostics.diagnostics()

def print_hash(args):
	assert len(args) == 1
	print 'ed2k:', lixian_hash_ed2k.hash_file(args[0])
	print 'dcid:', lixian_hash.dcid_hash_file(args[0])

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
		print lixian_help.welcome
	else:
		print lixian_help.help

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
	commands = {'login': login, 'logout': logout, 'download': download_task, 'list': list_task, 'add': add_task, 'delete': delete_task, 'pause': pause_task, 'restart': restart_task, 'rename': rename_task, 'info': lixian_info, 'config': lx_config, 'diagnostics': lx_diagnostics, 'hash': print_hash, 'help': lx_help}
	if command not in commands:
		usage()
		sys.exit(1)
	if '-h' in args or '--help' in args:
		lx_help([command])
	else:
		commands[command](args[1:])

if __name__ == '__main__':
	execute_command()


