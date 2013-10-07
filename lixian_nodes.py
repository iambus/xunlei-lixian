
import urllib2
import re

VOD_RANGE = '0-50'

def resolve_node_url(client, url, timeout=60):
	request = urllib2.Request(url, headers={'Cookie': 'gdriveid=' + client.get_gdriveid()})
	response = urllib2.urlopen(request, timeout=timeout)
	response.close()
	return response.geturl()

def switch_node_in_url(node_url, node):
	return re.sub(r'(http://)(vod\d+)(\.t\d+\.lixian\.vip\.xunlei\.com)', r'\1%s\3' % node, node_url)

def test_response_speed(response, max_size, max_duration):
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


def get_node_url_speed(url, gdriveid):
	request = urllib2.Request(url, headers={'Cookie': 'gdriveid=' + gdriveid})
	response = urllib2.urlopen(request, timeout=3)
	speed, size, duration = test_response_speed(response, 2*1000*1000, 3)
	response.close()
	return speed


def parse_vod_nodes(vod_nodes):
	if vod_nodes == 'all' or not vod_nodes:
		vod_nodes = VOD_RANGE
	nodes = []
	# remove duplicate nodes
	seen = set()
	def add(node):
		if node not in seen:
			nodes.append(node)
			seen.add(node)
	for expr in re.split(r'\s*,\s*', vod_nodes):
		if re.match(r'^\d+-\d+$', expr):
			start, end = map(int, expr.split('-'))
			if start <= end:
				for i in range(start, end + 1):
					add("vod%d" % i)
			else:
				for i in range(start, end -1, - 1):
					add("vod%d" % i)
		elif re.match(r'^\d+$', expr):
			add('vod'+expr)
		else:
			raise Exception("Invalid vod expr: " + expr)
	return nodes
