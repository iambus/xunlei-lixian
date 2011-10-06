#!/usr/bin/env python

from lixian import XunleiClient
import subprocess
import sys
import os
import os.path
import re

default_encoding = sys.getfilesystemencoding()
if default_encoding is None or default_encoding.lower() == 'ascii':
	default_encoding = 'utf-8'

LIXIAN_DEFAULT_COOKIES = os.path.join(os.getenv('USERPROFILE') or os.getenv('HOME'), '.xunlei.lixian.cookies')

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
			elif k.startswith('no-') and k[3:] in bools:
				options[k[3:]] = False
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
			self.__dict__['_args'] = args
			self.__dict__['_left'] = left
		def __getattr__(self, k):
			v = self._args.get(k, None)
			if v:
				return v
			if '_' in k:
				return self._args.get(k.replace('_', '-'), None)
		def __setattr__(self, k, v):
			self._args[k] = v
		def __getitem__(self, i):
			return self._left[i]
		def __len__(self):
			return len(self._left)
	return Args(options, left)

def parse_login_command_line(args, keys=[], bools=[], alias={}, default={}):
	common_keys = ['username', 'password', 'cookies']
	common_default = {'cookies': LIXIAN_DEFAULT_COOKIES}
	common_keys.extend(keys)
	common_default.update(default)
	args = parse_command_line(args, common_keys, bools, alias, common_default)
	if args.cookies == '-':
		args._args['cookies'] = None
	return args

def usage():
	print '''python lixian_cli.py login "Your Xunlei account" "Your password"

python lixian_cli.py list
python lixian_cli.py list --completed
python lixian_cli.py list --completed --name --original-url --download-url --no-status --no-task-id
python lixian_cli.py list --file zip

python lixian_cli.py download ed2k-url
python lixian_cli.py download --id task-id
python lixian_cli.py download --tool wget ed2k-url
python lixian_cli.py download --tool asyn ed2k-url
python lixian_cli.py download --tool urllib2 ed2k-url
python lixian_cli.py download ed2k-url --output "file to save"

python lixian_cli.py add url

python lixian_cli.py delete url
python lixian_cli.py delete --id task-id-to-delete
python lixian_cli.py delete --file file-name-on-cloud-to-delete

python lixian_cli.py pause ...

python lixian_cli.py restart ...

python lixian_cli.py logout
'''

def login(args):
	args = parse_login_command_line(args)
	if args.cookies == '-':
		args._args['cookies'] = None
	if len(args) < 1:
		raise RuntimeError('Not enough arguments')
	elif len(args) == 1:
		args.username = XunleiClient(cookie_path=args.cookies, login=False).get_username()
		args.password = args[0]
	elif len(args) == 2:
		args.username, args.password = list(args)
	elif len(args) == 3:
		args.username, args.password, args.cookies = list(args)
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
	args = parse_command_line(args, ['cookies'], default={'cookies': LIXIAN_DEFAULT_COOKIES})
	if len(args):
		raise RuntimeError('Too many arguments')
	print 'logging out from', args.cookies
	assert args.cookies
	client = XunleiClient(cookie_path=args.cookies, login=False)
	client.logout()

def urllib2_download(client, download_url, filename):
	'''In the case you don't even have wget...'''
	print 'Downloading', download_url, 'to', filename, '...'
	import urllib2
	request = urllib2.Request(download_url, headers={'Cookie': 'gdriveid='+client.get_gdriveid()})
	response = urllib2.urlopen(request)
	import shutil
	with open(filename, 'wb') as output:
		shutil.copyfileobj(response, output)

def asyn_download(client, download_url, filename):
	import lixian_download
	lixian_download.download(download_url, filename, headers={'Cookie': 'gdriveid='+str(client.get_gdriveid())})

def wget_download(client, download_url, filename):
	gdriveid = str(client.get_gdriveid())
	exit_code = subprocess.call(['wget', '--header=Cookie: gdriveid='+gdriveid, download_url, '-O', filename])
	if exit_code != 0:
		raise Exception('wget exited abnormaly')

def escape_filename(name):
	name = re.sub(r'&amp;', '&', name, flags=re.I)
	name = re.sub(r'[\\/:*?"<>|]', '-', name)
	return name

def download_single_task(client, download, task, output=None, delete=False):
	download_url = str(task['xunlei_url'])
	filename = output or escape_filename(task['name']).encode(default_encoding)
	referer = str(client.get_referer())
	gdriveid = str(client.get_gdriveid())

	download(client, download_url, filename)
	if task['type'] == 'ed2k':
		ed2k_link = task['original_url']
		from lixian_hash_ed2k import verify_ed2k_link
		if not verify_ed2k_link(filename, ed2k_link):
			raise Exception('ed2k hash check failed')

	if delete:
		client.delete_task(task)

def download_multiple_tasks(client, download, tasks, delete=False):
	for task in tasks:
		download_single_task(client, download, task, delete=delete)

def download_task(args):
	args = parse_login_command_line(args, ['tool', 'output', 'input'], ['delete', 'id', 'name', 'url'], alias={'o': 'output', 'i': 'input'}, default={'tool':'wget'})
	download = {'wget':wget_download, 'asyn':asyn_download, 'urllib2':urllib2_download}[args.tool]
	client = XunleiClient(args.username, args.password, args.cookies)
	links = None
	if len(args) > 1 or args.input:
		assert not(args.id or args.name or args.url or args.output)
		links = []
		links.extend(args)
		if args.input:
			with open(args.input) as x:
				links.extend(line.strip() for line in x.readlines() if line.strip())
		all_tasks = client.read_all_tasks()
		to_add = set(links)
		for t in all_tasks:
			for x in to_add:
				if link_equals(t['original_url'], x):
					to_add.remove(x)
					break
		if to_add:
			print 'Adding below tasks:'
			for link in to_add:
				print link
			self.add_batch_task(to_add)
			all_tasks = client.read_all_tasks()
		tasks = filter(lambda t: link_in(t['original_url'], links), all_tasks)
		# TODO: check if some task is missing
		download_multiple_tasks(client, download, tasks, delete=args.delete)
	else:
		if len(args) == 1:
			assert not args.url
			args.url = args[0]
		tasks = search_tasks(client, args, status='all', check=False)
		if not tasks:
			assert args.url
			print 'Adding new task %s ...' % args.url
			client.add_task(args.url)
			tasks = client.read_all_completed()
			tasks = filter_tasks(tasks, 'original_url', args.url)
		if args.output:
			assert len(tasks) == 1
			download_single_task(client, download, task, args.output, delete=args.delete)
		else:
			download_multiple_tasks(client, download, tasks, delete=args.delete)

def link_equals(x1, x2):
	if x1.startswith('ed2k://') and x2.startswith('ed2k://'):
		import urllib
		x1 = urllib.unquote(x1)
		x2 = urllib.unquote(x2)
		return x1 == x2
	else:
		return x1 == x2

def link_in(url, links):
	for link in links:
		if link_equals(url, link):
			return True

def filter_tasks(tasks, k, v):
	if k == 'name':
		matched = filter(lambda t: t[k].find(v) != -1, tasks)
	elif k == 'original_url':
		matched = filter(lambda t: link_equals(t[k], v), tasks)
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
		elif args.file or args.name:
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
	args = parse_login_command_line(args, [],
	                                ['all', 'completed',
	                                 'task-id', 'name', 'status', 'size', 'original-url', 'download-url',
	                                 'id', 'file', 'url',],
									default={'task-id': True, 'name': True, 'status': True})
	client = XunleiClient(args.username, args.password, args.cookies)
	client.set_page_size(100)
	if args.id or args.file or args.url or len(args):
		tasks = search_tasks(client, args, status=(args.completed and 'completed' or 'all'), check=False)
	elif args.completed:
		tasks = client.read_all_completed()
	else:
		tasks = client.read_all_tasks()
	columns = ['task-id', 'name', 'status', 'size', 'original-url', 'download-url']
	columns = filter(lambda k: getattr(args, k), columns)
	for t in tasks:
		for k in columns:
			if k == 'task-id':
				print t['id'],
			elif k == 'name':
				print t['name'].encode(default_encoding),
			elif k == 'status':
				print t['status_text'],
			elif k == 'size':
				print t['size'],
			elif k == 'original-url':
				print t['original_url'],
			elif k == 'download-url':
				print t['xunlei_url'],
			else:
				raise NotImplementedError()
		print

def add_task(args):
	args = parse_login_command_line(args, ['input'], alias={'i':'input'})
	assert len(args) or args.input
	client = XunleiClient(args.username, args.password, args.cookies)
	links = []
	links.extend(args)
	if args.input:
		with open(args.input) as x:
			links.extend(line.strip() for line in x.readlines() if line.strip())
	print 'Adding below tasks:'
	for link in links:
		print link
	client.add_batch_tasks(links)
	print 'All tasks added. Checking status...'
	tasks = client.read_all_tasks()
	for link in links:
		found = filter_tasks(tasks, 'original_url', link)
		if found:
			print found[0]['status_text'], link
		else:
			print 'unknown', link

def delete_task(args):
	args = parse_login_command_line(args, [], ['id', 'file', 'url', 'i', 'all'])
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
	args = parse_login_command_line(args, [], ['id', 'file', 'url', 'i', 'all'])
	client = XunleiClient(args.username, args.password, args.cookies)
	to_pause = search_tasks(client, args)
	print "Below files are going to be paused:"
	for x in to_pause:
		print x['name']
	client.pause_tasks(to_pause)

def restart_task(args):
	args = parse_login_command_line(args, [], ['id', 'file', 'url', 'i', 'all'])
	client = XunleiClient(args.username, args.password, args.cookies)
	to_restart = search_tasks(client, args)
	print "Below files are going to be restarted:"
	for x in to_restart:
		print x['name']
	client.restart_tasks(to_restart)

def lixian_info(args):
	args = parse_login_command_line(args)
	client = XunleiClient(args.username, args.password, args.cookies, login=False)
	print 'id:', client.get_username()
	print 'internalid:', client.get_userid()
	print 'gdriveid:', client.get_gdriveid()

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
	commands = {'login': login, 'logout': logout, 'download': download_task, 'list': list_task, 'add': add_task, 'delete': delete_task, 'pause': pause_task, 'restart': restart_task, 'info': lixian_info}
	if command not in commands:
		usage()
		sys.exit(1)
	commands[command](args[1:])

if __name__ == '__main__':
	execute_command()

#x = execute_command(['delete', '-i', '--cookies', 'xunlei.cookies', 'ed2k://|file|%5BSC-OL%5D%5BKaiji2%5D%5B01%5D%5BMKV%5D%5BX264_AAC%5D%5B1280X720%5D%5B6C77C65F%5D.gb.ass|56114|e39a590424b6bb0574c40989d199c91c|h=er4uegovpq3p2jjz7pejtqx242j5ioym|/'])
#execute_command(['download', '--cookies', 'xunlei.cookies', 'ed2k://|file|%5BSC-OL%5D%5BKaiji2%5D%5B07%5D%5BMKV%5D%5BX264_AAC%5D%5B1280X720%5D%5B7221E7AA%5D.gb.ass|53758|aadb39c8621fdd300655c7e82af30335|h=fdvhxzqqzocqkxuwltz6xm6x3vdhasnb|/'])

