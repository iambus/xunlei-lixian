from lixian_plugins.api import command


from lixian_cli_parser import command_line_parser
from lixian_cli_parser import with_parser
from lixian_cli_parser import command_line_option, command_line_value
from lixian_commands.util import parse_login, parse_colors, create_client
from lixian_config import get_config

from lixian_encoding import default_encoding
from lixian_colors import colors

import lixian_nodes

@command(usage='test download speed from multiple vod nodes')
@command_line_parser()
@with_parser(parse_login)
@with_parser(parse_colors)
@command_line_value('vod-nodes', default=get_config('vod-nodes', lixian_nodes.VOD_RANGE))
def speed_test(args):
	'''
	usage: lx speed_test [--vod-nodes=0-50] [id|name]
	'''
	assert len(args)
	client = create_client(args)
	import lixian_query
	tasks = lixian_query.search_tasks(client, args)
	if not tasks:
		raise Exception('No task found')
	task = tasks[0]
	urls = []
	if task['type'] == 'bt':
		subs, skipped, single_file = lixian_query.expand_bt_sub_tasks(task)
		if not subs:
			raise Exception('No files found')
		subs = [f for f in subs if f['size'] > 1000*1000] or subs # skip files with length < 1M
		if single_file:
			urls.append((subs[0]['xunlei_url'], subs[0]['name'], None))
		else:
			for f in subs:
				urls.append((f['xunlei_url'], f['name'], task['name']))
	else:
		urls.append((task['xunlei_url'], task['name'], None))
	url, filename, dirname = urls[0]
	name = dirname + '/' + filename if dirname else filename
	test_file(client, url, name, args)

def test_file(client, url, name, options):
	with colors(options.colors).cyan():
		print name.encode(default_encoding)
	# print 'File:', name.encode(default_encoding)
	# print 'Address:', url
	node_url = lixian_nodes.resolve_node_url(url, client.get_gdriveid(), timeout=3)
	# print 'Node:', node_url
	test_nodes(node_url, client.get_gdriveid(), options)

def test_nodes(node_url, gdriveid, options):
	nodes = lixian_nodes.parse_vod_nodes(options.vod_nodes)
	best = None
	best_speed = 0
	for node in nodes:
		# print 'Node:', node
		url = lixian_nodes.switch_node_in_url(node_url, node)
		try:
			speed = lixian_nodes.get_node_url_speed(url, gdriveid)
			if best_speed < speed:
				best = node
				best_speed = speed
			kb = int(speed/1000)
			# print 'Speed: %dKB/s' % kb, '.' * (kb /100)
			show_node_speed(node, kb, options)
		except Exception, e:
			show_node_error(node, e, options)
	if best:
		with colors(options.colors).green():
			print best,
		print "is the fastest node!"

def show_node_speed(node, kb, options):
	node = "%-5s " % node
	speed = '%dKB/s' % kb
	bar = '.' * (kb /100)
	whitespaces = ' ' * (79 - len(node) - len(bar) - len(speed))
	if kb >= 1000:
		with colors(options.colors).green():
			# print node + bar + whitespaces + speed
			with colors(options.colors).bold():
				print node[:-1],
			print bar + whitespaces + speed
	else:
		print node + bar + whitespaces + speed

def show_node_error(node, e, options):
	with colors(options.colors).red():
		print "%-5s %s" % (node, e)

