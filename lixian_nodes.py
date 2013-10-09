
import lixian_logging

import urllib2
import re

VOD_RANGE = '0-50'

def resolve_node_url(url, gdriveid, timeout=60):
	request = urllib2.Request(url, headers={'Cookie': 'gdriveid=' + gdriveid})
	response = urllib2.urlopen(request, timeout=timeout)
	response.close()
	return response.geturl()

def switch_node_in_url(node_url, node):
	return re.sub(r'(http://)(vod\d+)(\.t\d+\.lixian\.vip\.xunlei\.com)', r'\1%s\3' % node, node_url)


def switch_node(url, node, gdriveid):
	assert re.match(r'^vod\d+$', node)
	logger = lixian_logging.get_logger()
	logger.debug('Download URL: ' + url)
	try:
		url = resolve_node_url(url, gdriveid, timeout=60)
		logger.debug('Resolved URL: ' + url)
	except:
		import traceback
		logger.debug(traceback.format_exc())
		return url
	url = switch_node_in_url(url, node)
	logger.debug('Switch to node URL: ' + url)
	return url

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
				for i in range(start, end - 1, -1):
					add("vod%d" % i)
		elif re.match(r'^\d+$', expr):
			add('vod'+expr)
		else:
			raise Exception("Invalid vod expr: " + expr)
	return nodes

def get_best_node_url_from(node_url, nodes, gdriveid):
	best = None
	best_speed = 0
	logger = lixian_logging.get_logger()
	for node in nodes:
		url = switch_node_in_url(node_url, node)
		try:
			speed = get_node_url_speed(url, gdriveid)
			logger.debug("%s speed: %s" % (node, speed))
			if speed > best_speed:
				best_speed = speed
				best = url
		except Exception, e:
			logger.debug("%s error: %s" % (node, e))
	return best

def get_good_node_url_from(node_url, nodes, acceptable_speed, gdriveid):
	best = None
	best_speed = 0
	logger = lixian_logging.get_logger()
	for node in nodes:
		url = switch_node_in_url(node_url, node)
		try:
			speed = get_node_url_speed(url, gdriveid)
			logger.debug("%s speed: %s" % (node, speed))
			if speed > acceptable_speed:
				return url
			elif speed > best_speed:
				best_speed = speed
				best = url
		except Exception, e:
			logger.debug("%s error: %s" % (node, e))
	return best

def use_node_by_policy(url, vod_nodes, gdriveid, policy):
	nodes = parse_vod_nodes(vod_nodes)
	assert nodes
	logger = lixian_logging.get_logger()
	logger.debug('Download URL: ' + url)
	try:
		node_url = resolve_node_url(url, gdriveid, timeout=60)
		logger.debug('Resolved URL: ' + node_url)
	except:
		import traceback
		logger.debug(traceback.format_exc())
		return url
	default_node = re.match(r'http://(vod\d+)\.', node_url).group(1)
	if default_node not in nodes:
		nodes.insert(0, default_node)
	chosen = policy(node_url, nodes, gdriveid)
	if chosen:
		logger.debug('Switch to URL: ' + chosen)
		return chosen
	else:
		return node_url


def use_fastest_node(url, vod_nodes, gdriveid):
	return use_node_by_policy(url, vod_nodes, gdriveid, get_best_node_url_from)

def use_fast_node(url, vod_nodes, acceptable_speed, gdriveid):
	def policy(url, vod_nodes, gdriveid):
		return get_good_node_url_from(url, vod_nodes, acceptable_speed, gdriveid)
	return use_node_by_policy(url, vod_nodes, gdriveid, policy)

