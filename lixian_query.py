
__all__ = ['query', 'bt_query', 'user_query', 'Query',
           'query_tasks', 'find_tasks_to_download', 'search_tasks', 'expand_bt_sub_tasks']

import lixian_hash_bt
import lixian_hash_ed2k
import lixian_encoding


def link_normalize(url):
	from lixian_url import url_unmask, normalize_unicode_link
	url = url_unmask(url)
	if url.startswith('magnet:'):
		return 'bt://'+lixian_hash_bt.magnet_to_infohash(url).encode('hex')
	elif url.startswith('ed2k://'):
		return lixian_hash_ed2k.parse_ed2k_id(url)
	elif url.startswith('bt://'):
		return url.lower()
	elif url.startswith('http://') or url.startswith('ftp://'):
		return normalize_unicode_link(url)
	return url

def link_equals(x1, x2):
	return link_normalize(x1) == link_normalize(x2)


class TaskBase(object):
	def __init__(self, client, args):
		self.client = client
		if args.category:
			self.fetch_tasks = lambda: client.read_all_tasks_by_category(args.category)
			self.get_default = self.get_tasks
		elif args.deleted:
			self.fetch_tasks = client.read_all_deleted
			self.get_default = self.get_tasks
		elif args.expired:
			self.fetch_tasks = client.read_all_expired
			self.get_default = self.get_tasks
		elif args.completed:
			self.fetch_tasks = client.read_all_tasks
			self.get_default = lambda: filter(lambda x: x['status_text'] == 'completed', self.get_tasks())
		elif args.all:
			self.fetch_tasks = client.read_all_tasks
			self.get_default = self.get_tasks
		else:
			self.fetch_tasks = client.read_all_tasks
			self.get_default = lambda: []
		# TODO: check args.limit

		self.tasks = None
		self.files = {}

		self.jobs = [[], []]

	def get_tasks(self):
		if self.tasks is None:
			self.tasks = self.fetch_tasks()
		return self.tasks

	def refresh_tasks(self):
		self.tasks = self.fetch_tasks()
		return self.tasks

	def get_files(self, task):
		assert isinstance(task, dict), task
		id = task['id']
		if id in self.files:
			return self.files[id]
		self.files[id] = self.client.list_bt(task)
		return self.files[id]

	def find_task_by_id(self, id):
		assert isinstance(id, basestring), repr(id)
		for t in self.get_tasks():
			if t['id'] == str(id) or t['#'] == int(id):
				return t

	def get_task_by_id(self, id):
		t = self.find_task_by_id(id)
		if not t:
			raise Exception('No task found for id '+id)
		return t

	def find_task_by_hash(self, hash):
		for t in self.get_tasks():
			if t['type'] == 'bt' and t['bt_hash'].lower() == hash:
				return t

	def find_task_by_url(self, url):
		for t in self.get_tasks():
			if link_equals(t['original_url'], url):
				return t

	def get_task_by_url(self, url):
		t = self.find_task_by_url(url)
		if not t:
			raise Exception('No task found for ' + lixian_encoding.to_native(url))
		return t

	def add_url_task(self, url):
		self.jobs[0].append(url)

	def add_bt_task_by_hash(self, hash):
		self.jobs[1].append(['hash', hash])

	def add_bt_task_by_content(self, content, name):
		self.jobs[1].append(['content', (content, name)])

	def add_magnet_task(self, hash):
		self.jobs[1].append(['magnet', hash])

	def commit(self):
		urls, bts = self.jobs
		if urls:
			self.client.add_batch_tasks(map(lixian_encoding.try_native_to_utf_8, urls))
		for bt_type, value in bts:
			if bt_type == 'hash':
				print 'Adding bt task', value # TODO: print the thing user inputs (may be not hash)
				self.client.add_torrent_task_by_info_hash(value)
			elif bt_type == 'content':
				content, name = value
				print 'Adding bt task', name
				self.client.add_torrent_task_by_content(content)
			elif bt_type == 'magnet':
				print 'Adding magnet task', value # TODO: print the thing user inputs (may be not hash)
				self.client.add_task(value)
			else:
				raise NotImplementedError(bt_type)
		self.jobs = [[], []]
		self.refresh_tasks()

class Query(object):
	def __init__(self, base):
		self.bind(base)

	def bind(self, base):
		self.base = base
		self.client = base.client
		return self

	def prepare(self):
		pass

	def get_tasks(self):
		raise NotImplementedError()


##################################################
# register
##################################################

processors = []

bt_processors = []

# 0
# 1 -- builtin -- most
# 2 -- subs -- 0/[0-9]
# 4 -- magnet
# 5 -- user
# 6 -- extend url
# 7 -- plain url, bt url
# 9 -- default -- text search

def query(priority):
	assert isinstance(priority, (int, float))
	def register(processor):
		processors.append((priority, processor))
		return processor
	return register

def bt_query(priority):
	assert isinstance(priority, (int, float))
	def register(processor):
		bt_processors.append((priority, processor))
		return processor
	return register

def user_query(processor):
	return query(priority=5)(processor)

def load_default_queries():
	import lixian_queries

def load_plugin_queries():
	import os
	import os.path
	import re
	parser_dir = os.path.join(os.path.dirname(__file__), "lixian_plugins", "queries")
	parsers = os.listdir(parser_dir)
	parsers = [re.sub(r'\.py$', '', p) for p in parsers if p.endswith('.py') and not p.startswith('_')]
	for p in parsers:
		__import__('lixian_plugins.queries.' + p)


##################################################
# query
##################################################

def to_query(base, arg, processors):
	for _, process in sorted(processors):
		q = process(base, arg)
		if q:
			return q
	raise NotImplementedError('No proper query process found for: ' + arg)

def merge_tasks(tasks):
	result_tasks = []
	task_mapping = {}
	for task in tasks:
		if type(task) == dict:
			id = task['id']
			if id in task_mapping:
				if 'index' in task and 'files' in task_mapping[id]:
					task_mapping[id]['files'].append(task['index'])
			else:
				if 'index' in task:
					t = dict(task)
					t['files'] = [t['index']]
					del t['index']
					result_tasks.append(t)
					task_mapping[id] = t
				else:
					result_tasks.append(task)
					task_mapping[id] = task
		else:
			if task in task_mapping:
				pass
			else:
				result_tasks.append(task)
				task_mapping[task] = task
	return result_tasks

def enrich_bt(base, tasks):
	for t in tasks:
		if t['type'] == 'bt':
			# XXX: a dirty trick to cache requests
			t['base'] = base

def query_tasks(client, options, args, readonly=False):
	load_default_queries() # IMPORTANT: init default queries
	base = TaskBase(client, options)
	if not len(args):
		return base.get_default()
	# analysis queries
	queries = [to_query(base, arg, bt_processors if options.torrent else processors) for arg in args]
	if not readonly:
		# prepare actions (e.g. add tasks)
		for query in queries:
			query.prepare()
		# commit and refresh task list
		base.commit()
	# merge results
	tasks = []
	for query in queries:
		tasks += query.get_tasks()
	tasks = merge_tasks(tasks)
	enrich_bt(base, tasks)
	return tasks

##################################################
# compatible APIs
##################################################

def find_tasks_to_download(client, args):
	links = []
	links.extend(args)
	if args.input:
		import fileinput
		links.extend(line.strip() for line in fileinput.input(args.input) if line.strip())
	return query_tasks(client, args, list(args))

def search_tasks(client, args):
	return query_tasks(client, args, list(args), readonly=True)

def expand_bt_sub_tasks(task):
	files = task['base'].get_files(task) # XXX: a dirty trick to cache requests
	not_ready = []
	single_file = False
	if len(files) == 1 and files[0]['name'] == task['name']:
		single_file = True
	if 'files' in task:
		ordered_files = []
		for i in task['files']:
			assert isinstance(i, int)
			t = files[i]
			if t['status_text'] != 'completed':
				not_ready.append(t)
			else:
				ordered_files.append(t)
		files = ordered_files
	return files, not_ready, single_file


