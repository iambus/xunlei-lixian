from lixian_plugins.api import command


from lixian_cli_parser import command_line_parser
from lixian_cli_parser import with_parser
from lixian_cli_parser import command_line_option, command_line_value
from lixian_commands.util import parse_login, parse_colors, create_client
from lixian_config import get_config

from lixian_encoding import default_encoding
from lixian_colors import colors

import urllib2
import re

VOD_RANGE = '0-50'

@command(usage='test download speed from multiple vod nodes')
@command_line_parser()
@with_parser(parse_login)
@with_parser(parse_colors)
@command_line_value('vod-nodes', default=get_config('vod-nodes', VOD_RANGE))
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
	node_url = resolve_node_url(client, url)
	# print 'Node:', node_url
	test_nodes(node_url, client.get_gdriveid(), options)

def get_nodes(vod_nodes):
	if vod_nodes == 'all' or not vod_nodes:
		vod_nodes = VOD_RANGE
	nodes = []
	for expr in re.split(r'\s*,\s*', vod_nodes):
		if re.match(r'^\d+-\d+$', expr):
			start, end = map(int, expr.split('-'))
			if start <= end:
				for i in range(start, end + 1):
					nodes.append("vod%d" % i)
			else:
				for i in range(start, end -1, - 1):
					nodes.append("vod%d" % i)
		elif re.match(r'^\d+$', expr):
			nodes.append('vod'+expr)
		else:
			raise Exception("Invalid vod expr: " + expr)
	return nodes

def test_nodes(node_url, gdriveid, options):
	nodes = get_nodes(options.vod_nodes)
	for node in nodes:
		# print 'Node:', node
		url = re.sub(r'(http://)(vod\d+)(\.t\d+\.lixian\.vip\.xunlei\.com)', r'\1%s\3' % node, node_url)
		try:
			speed = test_node(url, gdriveid)
			kb = int(speed/1000)
			# print 'Speed: %dKB/s' % kb, '.' * (kb /100)
			show_node_speed(node, kb, options)
		except Exception, e:
			show_node_error(node, e, options)

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

def test_node(url, gdriveid):
	request = urllib2.Request(url, headers={'Cookie': 'gdriveid=' + gdriveid})
	response = urllib2.urlopen(request, timeout=3)
	speed, size, duration = test_stream(response, 2*1000*1000, 3)
	response.close()
	# print "Duration:", duration
	# print "Data:", size
	# print "Speed:", speed
	return speed

def test_stream(response, max_size, max_duration):
	import time
	current_duration = 0
	current_size = 0
	start = time.clock()
	while current_duration < max_duration and current_size < max_size:
		data = response.read(max_size - current_size)
		if not data:
			# print "End of file"
			break
		current_size += len(data)
		end = time.clock()
		current_duration = end - start
	if current_size < 1024:
		raise Exception("Sample too small: %d" % current_size)
	return current_size / current_duration, current_size, current_duration

# FIXME: duplicate with lixian_commands/download.py
def resolve_node_url(client, url):
	request = urllib2.Request(url, headers={'Cookie': 'gdriveid=' + client.get_gdriveid()})
	response = urllib2.urlopen(request, timeout=3)
	response.close()
	return response.geturl()
