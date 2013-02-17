
import re

name_filters = {}
task_filters = {}

def find_matcher(keyword, filters):
	for p in filters:
		if re.search(p, keyword):
			return filters[p]

def has_task_filter(keyword):
	return bool(find_matcher(keyword, task_filters))

def match_thing(thing, keyword):
	m = find_matcher(keyword, task_filters if type(thing) == dict else name_filters)
	if m:
		return bool(m(keyword, thing))
	else:
		return None

def filter_tasks(tasks, keyword):
	# XXX: should return None if thing list is empty?
	m = find_matcher(keyword, task_filters)
	if m:
		return filter(lambda x: m(keyword, x), tasks)

def filter_things(things, keyword):
	# XXX: return None if thing list is empty?
	if not things:
		return
	assert len(set(map(type, things))) == 1
	filters = task_filters if type(things[0]) == dict else name_filters
	m = find_matcher(keyword, filters)
	if m:
		return filter(lambda x: m(keyword, x), things)

def define_task_filter(pattern, matcher):
	task_filters[pattern] = matcher

def define_name_filter(pattern, matcher):
	name_filters[pattern] = matcher
	task_filters[pattern] = lambda k, x: matcher(k, x['name'])

def task_filter(pattern=None, protocol=None):
	assert bool(pattern) ^ bool(protocol)
	def define_filter(matcher):
		if pattern:
			define_task_filter(pattern, matcher)
		else:
			assert re.match(r'^\w+$', protocol), protocol
			define_task_filter(r'^%s:' % protocol, lambda k, x: matcher(re.sub(r'^\w+:', '', k), x))
		return matcher
	return define_filter

def name_filter(pattern=None, protocol=None):
	# FIXME: duplicate code
	assert bool(pattern) ^ bool(protocol)
	def define_filter(matcher):
		if pattern:
			define_name_filter(pattern, matcher)
		else:
			assert re.match(r'^\w+$', protocol), protocol
			define_name_filter(r'^%s:' % protocol, lambda k, x: matcher(re.sub(r'^\w+:', '', k), x))
		return matcher
	return define_filter

def load_filters():
	import os
	import os.path
	filter_dir = os.path.dirname(__file__)
	filters = os.listdir(filter_dir)
	filters = [re.sub(r'\.py$', '', p) for p in filters if p.endswith('.py') and not p.startswith('_')]
	for p in filters:
		__import__('lixian_plugins.filters.' + p)
