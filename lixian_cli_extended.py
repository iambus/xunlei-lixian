
from lixian_cli_parser import parse_command_line
from lixian_cli_parser import expand_command_line

##################################################

def print_hash(args):
	#assert len(args) == 1
	import lixian_hash
	#import lixian_hash_ed2k
	#print 'ed2k:', lixian_hash_ed2k.hash_file(args[0])
	#print 'dcid:', lixian_hash.dcid_hash_file(args[0])
	lixian_hash.main(expand_command_line(args))

hash_help = '''
lx hash --sha1 file...
lx hash --md5 file...
lx hash --md4 file...
lx hash --ed2k file...
lx hash --info-hash xxx.torrent...
lx hash --verify-sha1 file hash
lx hash --verify-md5 file hash
lx hash --verify-md4 file hash
lx hash --verify-ed2k file ed2k://...
lx hash --verify-bt file xxx.torrent
'''

##################################################

def lx_diagnostics(args):
	import lixian_diagnostics
	lixian_diagnostics.diagnostics()

diagnostics_help = 'usage: lx diagnostics'

##################################################

def decode_url(args):
	from lixian_url import url_unmask
	for x in args:
		print url_unmask(x)

decode_url_help = 'usage: lx decode-url thunder://...'

##################################################

def kuai(args):
	import lixian_kuai
	lixian_kuai.main(args)

kuai_help = '''usage: lx kuai http://kuai.xunlei.com/d/xxx...

Note that you can simply use:
 lx add http://kuai.xunlei.com/d/xxx...
or:
 lx download http://kuai.xunlei.com/d/xxx...
'''

##################################################

def extend_links(args):
	args = parse_command_line(args, [], ['name'])
	import lixian_tasks_extended
	for x in (lixian_tasks_extended.extend_links if not args.name else lixian_tasks_extended.extend_links_name)(args):
		print x

extend_links_help = '''usage: lx extend-links http://kuai.xunlei.com/d/... http://www.verycd.com/topics/...

parse and print links from pages

lx extend-links urls...
lx extend-links --name urls...
'''

##################################################

def list_torrent(args):
	args = parse_command_line(args, [], ['size'])
	for p in args:
		with open(p, 'rb') as stream:
			from lixian_hash_bt import bdecode
			info = bdecode(stream.read())['info']
			print '*', info['name'].decode('utf-8')
			for f in info['files']:
				path = '/'.join(f['path']).decode('utf-8')
				if args.size:
					from lixian_util import format_size
					print u'%s (%s)' % (path, format_size(f['length']))
				else:
					print path

##################################################

def get_torrent(args):
	from lixian_cli import parse_login_command_line
	args = parse_login_command_line(args)
	from lixian import XunleiClient
	client = XunleiClient(args.username, args.password, args.cookies)
	for id in args:
		id = id.lower()
		import re
		if re.match(r'[a-fA-F0-9]{40}$', id):
			torrent = client.get_torrent_file_by_info_hash(id)
		elif re.match(r'#?\d+$', id):
			tasks = client.read_all_tasks()
			from lixian_tasks import find_task_by_id
			task = find_task_by_id(tasks, id)
			assert task, id + ' not found'
			id = task['bt_hash']
			id = id.lower()
			torrent = client.get_torrent_file_by_info_hash(id)
		else:
			raise NotImplementedError()
		path = id + '.torrent'
		print path
		with open(path, 'wb') as output:
			output.write(torrent)

##################################################

def export_aria2(args):
	import lixian_cli
	args = lixian_cli.parse_login_command_line(args)
	from lixian import XunleiClient
	client = XunleiClient(args.username, args.password, args.cookies)
	import lixian_tasks
	tasks = lixian_tasks.search_tasks(client, args, status=(args.completed and 'completed' or 'all'))
	files = []
	for task in tasks:
		if task['type'] == 'bt':
			subs, skipped, single_file = lixian_tasks.expand_bt_sub_tasks(client, task)
			if not subs:
				continue
			if single_file:
				files.append((subs[0]['xunlei_url'], subs[0]['name'], None))
			else:
				for f in subs:
					import os.path
					files.append((f['xunlei_url'], f['name'], task['name']))
		else:
			files.append((task['xunlei_url'], task['name'], None))
	for url, name, dir in files:
		print url
		from lixian_encoding import default_encoding
		print '  out=' + name.encode(default_encoding)
		if dir:
			print '  dir=' + dir.encode(default_encoding)
		print '  header=Cookie: gdriveid=' + client.get_gdriveid()


##################################################
# update helps
##################################################

extended_commands = [
		['hash', print_hash, 'compute hashes', hash_help.strip()],
		['diagnostics', lx_diagnostics, 'print helpful information for diagnostics', diagnostics_help],
		['decode-url', decode_url, 'convert thunder:// (and more) to normal url', decode_url_help],
		['kuai', kuai, 'parse links from kuai.xunlei.com', kuai_help],
		['extend-links', extend_links, 'parse links', extend_links_help],
		['list-torrent', list_torrent, 'list files in local .torrent', 'usage: lx list-torrent [--size] xxx.torrent...'],
		['get-torrent', get_torrent, 'get .torrent by task id or info hash', 'usage: lx get-torrent [info-hash|task-id]...'],
		['export-aria2', export_aria2, 'export task download urls as aria2 format', 'usage: lx export-aria2 [id|name]...'],
		]

commands = dict(x[:2] for x in extended_commands)

def update_helps(commands):
	helps = dict((name, doc) for (name, usage, doc) in commands)

	if commands:
		import lixian_help
		lixian_help.extended_usage = '''\nExtended commands:
''' + lixian_help.join_commands([(x[0], x[1]) for x in commands])

	for name, usage, doc in commands:
		assert not hasattr(lixian_help, name)
		setattr(lixian_help, name, doc)

update_helps([(x[0], x[2], x[3]) for x in extended_commands])

