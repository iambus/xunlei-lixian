
import lixian_download_tools
import lixian_nodes
from lixian_commands.util import *
from lixian_cli_parser import *
from lixian_config import *
from lixian_encoding import default_encoding
from lixian_colors import colors
import lixian_help
import lixian_query
import lixian_hash
import lixian_hash_bt
import lixian_hash_ed2k

import os
import os.path
import re

def ensure_dir_exists(dirname):
	if dirname and not os.path.exists(dirname):
		try:
			os.makedirs(dirname)
		except os.error:
			if not os.path.exists(dirname):
				raise

def escape_filename(name):
	amp = re.compile(r'&(amp;)+', flags=re.I)
	name = re.sub(amp, '&', name)
	name = re.sub(r'[\\/:*?"<>|]', '-', name)
	return name

def safe_encode_native_path(path):
	return path.encode(default_encoding).decode(default_encoding).replace('?', '-').encode(default_encoding)

def verify_basic_hash(path, task):
	if os.path.getsize(path) != task['size']:
		print 'hash error: incorrect file size (%s != %s)' % (os.path.getsize(path), task['size'])
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

def download_file(client, path, task, options):
	download_tool = lixian_download_tools.get_tool(options['tool'])

	resuming = options.get('resuming')
	overwrite = options.get('overwrite')
	mini_hash = options.get('mini_hash')
	no_hash = options.get('no_hash')

	url = str(task['xunlei_url'])
	if options['node']:
		if options['node'] == 'best' or options['node'] == 'fastest':
			from lixian_util import parse_size
			if task['size'] >= parse_size(options['node_detection_threshold']):
				url = lixian_nodes.use_fastest_node(url, options['vod_nodes'], client.get_gdriveid())
		elif options['node'] == 'fast':
			from lixian_util import parse_size
			if task['size'] >= parse_size(options['node_detection_threshold']):
				url = lixian_nodes.use_fast_node(url, options['vod_nodes'], parse_size(options['node_detection_acceptable']), client.get_gdriveid())
		else:
			url = lixian_nodes.switch_node(url, options['node'], client.get_gdriveid())

	def download1(download, path):
		if not os.path.exists(path):
			download()
		elif not resuming:
			if overwrite:
				download()
			else:
				raise Exception('%s already exists. Please try --continue or --overwrite' % path)
		else:
			if download.finished():
				pass
			else:
				download()

	def download1_checked(client, url, path, size):
		download = download_tool(client=client, url=url, path=path, size=size, resuming=resuming)
		checked = 0
		while checked < 10:
			download1(download, path)
			if download.finished():
				break
			else:
				checked += 1
		assert os.path.getsize(path) == size, 'incorrect downloaded file size (%s != %s)' % (os.path.getsize(path), size)

	def download2(client, url, path, task):
		size = task['size']
		if mini_hash and resuming and verify_mini_hash(path, task):
			return
		download1_checked(client, url, path, size)
		verify = verify_basic_hash if no_hash else verify_hash
		if not verify(path, task):
			with colors(options.get('colors')).yellow():
				print 'hash error, redownloading...'
			os.rename(path, path + '.error')
			download1_checked(client, url, path, size)
			if not verify(path, task):
				raise Exception('hash check failed')

	download2(client, url, path, task)


def download_single_task(client, task, options):
	output = options.get('output')
	output = output and os.path.expanduser(output)
	output_dir = options.get('output_dir')
	output_dir = output_dir and os.path.expanduser(output_dir)
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
			with colors(options.get('colors')).yellow():
				print 'skip task %s as the status is %s' % (task['name'].encode(default_encoding), task['status_text'])
			return

	if output:
		output_path = output
		output_dir = os.path.dirname(output)
		output_name = os.path.basename(output)
	else:
		output_name = safe_encode_native_path(escape_filename(task['name']))
		output_dir = output_dir or '.'
		output_path = os.path.join(output_dir, output_name)

	if task['type'] == 'bt':
		files, skipped, single_file = lixian_query.expand_bt_sub_tasks(task)
		if single_file:
			dirname = output_dir
		else:
			if no_bt_dir:
				output_path = os.path.dirname(output_path)
			dirname = output_path
		assert dirname # dirname must be non-empty, otherwise dirname + os.path.sep + ... might be dangerous
		ensure_dir_exists(dirname)
		for t in skipped:
			with colors(options.get('colors')).yellow():
				print 'skip task %s/%s (%s) as the status is %s' % (str(t['id']), t['index'], t['name'].encode(default_encoding), t['status_text'])
		if mini_hash and resuming and verify_mini_bt_hash(dirname, files):
			print task['name'].encode(default_encoding), 'is already done'
			if delete and 'files' not in task:
				client.delete_task(task)
			return
		if not single_file:
			with colors(options.get('colors')).green():
				print output_name + '/'
		for f in files:
			name = f['name']
			if f['status_text'] != 'completed':
				print 'Skipped %s file %s ...' % (f['status_text'], name.encode(default_encoding))
				continue
			if not single_file:
				print name.encode(default_encoding), '...'
			else:
				with colors(options.get('colors')).green():
					print name.encode(default_encoding), '...'
			# XXX: if file name is escaped, hashing bt won't get correct file
			splitted_path = map(escape_filename, name.split('\\'))
			name = safe_encode_native_path(os.path.join(*splitted_path))
			path = dirname + os.path.sep + name # fix issue #82
			if splitted_path[:-1]:
				subdir = safe_encode_native_path(os.path.join(*splitted_path[:-1]))
				subdir = dirname + os.path.sep + subdir # fix issue #82
				ensure_dir_exists(subdir)
			download_file(client, path, f, options)
#		if save_torrent_file:
#			info_hash = str(task['bt_hash'])
#			if single_file:
#				torrent = os.path.join(dirname, escape_filename(task['name']).encode(default_encoding) + '.torrent')
#			else:
#				torrent = os.path.join(dirname, info_hash + '.torrent')
#			if os.path.exists(torrent):
#				pass
#			else:
#				content = client.get_torrent_file_by_info_hash(info_hash)
#				with open(torrent, 'wb') as ouput_stream:
#					ouput_stream.write(content)
#		if not no_hash:
#			torrent_file = client.get_torrent_file(task)
#			print 'Hashing bt ...'
#			from lixian_progress import SimpleProgressBar
#			bar = SimpleProgressBar()
#			file_set = [f['name'].encode('utf-8').split('\\') for f in files] if 'files' in task else None
#			verified = lixian_hash_bt.verify_bt(output_path, lixian_hash_bt.bdecode(torrent_file)['info'], file_set=file_set, progress_callback=bar.update)
#			bar.done()
#			if not verified:
#				# note that we don't delete bt download folder if hash failed
#				raise Exception('bt hash check failed')
	else:
		ensure_dir_exists(output_dir)

		with colors(options.get('colors')).green():
			print output_name, '...'
		download_file(client, output_path, task, options)

	if delete and 'files' not in task:
		client.delete_task(task)

def download_multiple_tasks(client, tasks, options):
	for task in tasks:
		download_single_task(client, task, options)
	skipped = filter(lambda t: t['status_text'] != 'completed', tasks)
	if skipped:
		with colors(options.get('colors')).yellow():
			print "Below tasks were skipped as they were not ready:"
		for task in skipped:
			print task['id'], task['status_text'], task['name'].encode(default_encoding)

@command_line_parser(help=lixian_help.download)
@with_parser(parse_login)
@with_parser(parse_colors)
@with_parser(parse_logging)
@command_line_value('tool', default=get_config('tool', 'wget'))
@command_line_value('input', alias='i')
@command_line_value('output', alias='o')
@command_line_value('output-dir', default=get_config('output-dir'))
@command_line_option('torrent', alias='bt')
@command_line_option('all')
@command_line_value('category')
@command_line_value('limit', default=get_config('limit'))
@command_line_value('page-size', default=get_config('page-size'))
@command_line_option('delete', default=get_config('delete'))
@command_line_option('continue', alias='c', default=get_config('continue'))
@command_line_option('overwrite')
@command_line_option('mini-hash', default=get_config('mini-hash'))
@command_line_option('hash', default=get_config('hash', True))
@command_line_option('bt-dir', default=True)
@command_line_option('save-torrent-file')
@command_line_option('watch')
@command_line_option('watch-present')
@command_line_value('watch-interval', default=get_config('watch-interval', '3m'))
@command_line_value('node', default=get_config('node'))
@command_line_value('node-detection-threshold', default=get_config('node-detection-threshold', '100M'))
@command_line_value('node-detection-acceptable', default=get_config('node-detection-acceptable', '1M'))
@command_line_value('vod-nodes', default=get_config('vod-nodes', lixian_nodes.VOD_RANGE))
def download_task(args):
	assert len(args) or args.input or args.all or args.category, 'Not enough arguments'
	lixian_download_tools.get_tool(args.tool) # check tool
	download_args = {'tool': args.tool,
	                 'output': args.output,
	                 'output_dir': args.output_dir,
	                 'delete': args.delete,
	                 'resuming': args._args['continue'],
	                 'overwrite': args.overwrite,
	                 'mini_hash': args.mini_hash,
	                 'no_hash': not args.hash,
	                 'no_bt_dir': not args.bt_dir,
	                 'save_torrent_file': args.save_torrent_file,
	                 'node': args.node,
	                 'node_detection_threshold': args.node_detection_threshold,
	                 'node_detection_acceptable': args.node_detection_acceptable,
	                 'vod_nodes': args.vod_nodes,
	                 'colors': args.colors}
	client = create_client(args)
	query = lixian_query.build_query(client, args)
	query.query_once()

	def sleep(n):
		assert isinstance(n, (int, basestring)), repr(n)
		import time
		if isinstance(n, basestring):
			n, u = re.match(r'^(\d+)([smh])?$', n.lower()).groups()
			n = int(n) * {None: 1, 's': 1, 'm': 60, 'h': 3600}[u]
		time.sleep(n)

	if args.watch_present:
		assert not args.output, 'not supported with watch option yet'
		tasks = query.pull_completed()
		while True:
			if tasks:
				download_multiple_tasks(client, tasks, download_args)
			if not query.download_jobs:
				break
			if not tasks:
				sleep(args.watch_interval)
			query.refresh_status()
			tasks = query.pull_completed()

	elif args.watch:
		assert not args.output, 'not supported with watch option yet'
		tasks = query.pull_completed()
		while True:
			if tasks:
				download_multiple_tasks(client, tasks, download_args)
			if (not query.download_jobs) and (not query.queries):
				break
			if not tasks:
				sleep(args.watch_interval)
			query.refresh_status()
			query.query_search()
			tasks = query.pull_completed()

	else:
		tasks = query.peek_download_jobs()
		if args.output:
			assert len(tasks) == 1
			download_single_task(client, tasks[0], download_args)
		else:
			download_multiple_tasks(client, tasks, download_args)
