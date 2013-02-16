
import os
import re

import lixian_url
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
		self.tasks = None
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

		self.jobs = [[], []]

	def get_tasks(self):
		if self.tasks is None:
			self.tasks = self.fetch_tasks()
		return self.tasks

	def refresh_tasks(self):
		self.tasks = self.fetch_tasks()
		return self.tasks

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
# queries
##################################################

class SingleTaskQuery(Query):
	def __init__(self, base, t):
		super(SingleTaskQuery, self).__init__(base)
		self.id = t['id']

	def get_tasks(self):
		return [self.base.get_task_by_id(self.id)]

def single_id_processor(base, x):
	if not re.match(r'^\d+/?$', x):
		return
	n = x.rstrip('/')
	t = base.find_task_by_id(n)
	if t:
		return SingleTaskQuery(base, t)

##################################################

class MultipleTasksQuery(Query):
	def __init__(self, base, tasks):
		super(MultipleTasksQuery, self).__init__(base)
		self.tasks = tasks

	def get_tasks(self):
		return map(self.base.get_task_by_id, (t['id'] for t in self.tasks))

def range_id_processor(base, x):
	m = re.match(r'^#?(\d+)-(\d+)$', x)
	if not m:
		return
	begin = int(m.group(1))
	end = int(m.group(2))
	tasks = base.get_tasks()
	if begin <= end:
		found = filter(lambda x: begin <= x['#'] <= end, tasks)
	else:
		found = reversed(filter(lambda x: end <= x['#'] <= begin, tasks))
	if found:
		return MultipleTasksQuery(base, found)

##################################################

class SubTaskQuery(Query):
	def __init__(self, base, t, subs):
		super(SubTaskQuery, self).__init__(base)
		self.task = t
		self.subs = subs

	def get_tasks(self):
		result = []
		task = self.base.get_task_by_id(self.task['id'])
		for i in self.subs:
			t = dict(task)
			t['index'] = i
			result.append(t)
		return result

def sub_id_processor(base, x):
	m = re.match(r'^#?(\d+)/([-.\w\[\],\s*]+)$', x)
	if not m:
		return
	task_id, sub_id = m.groups()
	task = base.find_task_by_id(task_id)
	if not task:
		return

	assert task['type'] == 'bt', 'task %s is not a bt task' % lixian_encoding.to_native(task['name'])
	subs = []
	if re.match(r'\[.*\]', sub_id):
		for sub_id in re.split(r'\s*,\s*', sub_id[1:-1]):
			assert re.match(r'^\d+(-\d+)?|\.\w+$', sub_id), sub_id
			if sub_id.startswith('.'):
				subs.append(sub_id)
			elif '-' in sub_id:
				start, end = map(int, sub_id.split('-'))
				r = range(start, end+1) if start <= end else reversed(range(end, start+1))
				for i in r:
					subs.append(str(i))
			else:
				assert re.match(r'^\d+$', sub_id), sub_id
				subs.append(sub_id)
	elif re.match(r'^\.\w+$', sub_id):
		subs.append(sub_id)
	elif sub_id == '*':
		subs.append(sub_id)
	else:
		assert re.match(r'^\d+$', sub_id), sub_id
		subs.append(sub_id)
	return SubTaskQuery(base, task, subs)

##################################################

class DateQuery(Query):
	def __init__(self, base, x):
		super(DateQuery, self).__init__(base)
		self.text = x

	def get_tasks(self):
		return filter(lambda t: t['name'].lower().find(self.text.lower()) != -1, self.base.get_tasks())

def date_processor(base, x):
	if re.match(r'^\d{4}\.\d{2}\.\d{2}$', x):
		matched = filter(lambda t: t['date'] == x, base.get_tasks())
		if matched:
			return MultipleTasksQuery(base, matched)

##################################################

class BtHashProcessor(Query):
	def __init__(self, base, x):
		super(BtHashProcessor, self).__init__(base)
		self.hash = re.match(r'^(?:bt://)?([0-9a-f]{40})$', x, flags=re.I).group(1).lower()
		self.task = self.base.find_task_by_hash(self.hash)

	def prepare(self):
		if not self.task:
			self.base.add_bt_task_by_hash(self.hash)

	def get_tasks(self):
		t = self.base.find_task_by_hash(self.hash)
		assert t, 'Task not found: bt://' + self.hash
		return [t]


def bt_hash_processor(base, x):
	if re.match(r'^(bt://)?[0-9a-f]{40}$', x, flags=re.I):
		return BtHashProcessor(base, x)

##################################################

class LocalBtQuery(Query):
	def __init__(self, base, x):
		super(LocalBtQuery, self).__init__(base)
		self.path = x
		self.hash = lixian_hash_bt.info_hash(self.path)
		self.task = self.base.find_task_by_hash(self.hash)
		with open(self.path, 'rb') as stream:
			self.torrent = stream.read()

	def prepare(self):
		if not self.task:
			self.base.add_bt_task_by_content(self.torrent, self.path)

	def get_tasks(self):
		t = self.base.find_task_by_hash(self.hash)
		assert t, 'Task not found: bt://' + self.hash
		return [t]

def local_bt_processor(base, x):
	if x.lower().endswith('.torrent') and os.path.exists(x):
		return LocalBtQuery(base, x)

##################################################

class MagnetQuery(Query):
	def __init__(self, base, x):
		super(MagnetQuery, self).__init__(base)
		self.url = x
		self.hash = lixian_hash_bt.magnet_to_infohash(x).encode('hex').lower()
		self.task = self.base.find_task_by_hash(self.hash)

	def prepare(self):
		if not self.task:
			self.base.add_magnet_task(self.url)

	def get_tasks(self):
		t = self.base.find_task_by_hash(self.hash)
		assert t, 'Task not found: bt://' + self.hash
		return [t]

def magnet_processor(base, url):
	if re.match(r'magnet:', url):
		return MagnetQuery(base, url)

##################################################

class BatchUrlsQuery(Query):
	def __init__(self, base, urls):
		super(BatchUrlsQuery, self).__init__(base)
		self.urls = urls

	def prepare(self):
		for url in self.urls:
			if not self.base.find_task_by_url(url):
				self.base.add_url_task(url)

	def get_tasks(self):
		return map(self.base.get_task_by_url, self.urls)

def url_extend_processor(base, url):
	import lixian_extend_links
	extended = lixian_extend_links.try_to_extend_link(url)
	if extended:
		extended = map(lixian_extend_links.to_url, extended)
		return BatchUrlsQuery(base, extended)

##################################################

class UrlQuery(Query):
	def __init__(self, base, x):
		super(UrlQuery, self).__init__(base)
		self.url = lixian_url.url_unmask(x)
		self.task = self.base.find_task_by_url(self.url)

	def prepare(self):
		if not self.task:
			self.base.add_url_task(self.url)

	def get_tasks(self):
		t = self.base.find_task_by_url(self.url)
		assert t, 'Task not found: bt://' + self.url
		return [t]

def url_processor(base, url):
	if re.match(r'\w+://', url):
		return UrlQuery(base, url)

##################################################

class BtUrlQuery(Query):
	def __init__(self, base, url, torrent):
		super(BtUrlQuery, self).__init__(base)
		self.url = url
		self.torrent = torrent
		self.hash = lixian_hash_bt.info_hash_from_content(self.torrent)
		self.task = self.base.find_task_by_hash(self.hash)

	def prepare(self):
		if not self.task:
			self.base.add_bt_task_by_content(self.torrent, self.url)

	def get_tasks(self):
		t = self.base.find_task_by_hash(self.hash)
		assert t, 'Task not found: bt://' + self.hash
		return [t]

def bt_url_processor(base, url):
	if not re.match(r'http://', url):
		return
	print 'Downloading torrent file from', url
	import urllib2
	torrent = urllib2.urlopen(url, timeout=60).read()
	return BtUrlQuery(base, url, torrent)

##################################################

class DefaultQuery(Query):
	def __init__(self, base, x):
		super(DefaultQuery, self).__init__(base)
		self.text = x

	def get_tasks(self):
		return filter(lambda t: t['name'].lower().find(self.text.lower()) != -1, self.base.get_tasks())

def default_processor(base, x):
	return DefaultQuery(base, x)

##################################################
# query list
##################################################

processors = [single_id_processor,
              range_id_processor,
              sub_id_processor,
              date_processor,
              bt_hash_processor,
              local_bt_processor,
              magnet_processor,
              url_extend_processor,
              url_processor,
              default_processor]

bt_processors = [single_id_processor,
                 range_id_processor,
                 sub_id_processor,
                 date_processor,
                 bt_hash_processor,
                 local_bt_processor,
                 magnet_processor,
                 url_extend_processor,
                 bt_url_processor,
                 default_processor]

def to_query(base, arg, processors):
	for process in processors:
		q = process(base, arg)
		if q:
			return q
	raise NotImplementedError('No proper query process found for: ' + arg)

def merge_bt_sub_tasks(tasks):
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


def query_tasks(client, options, args, readonly=False):
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
	return merge_bt_sub_tasks(tasks)

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

def expand_bt_sub_tasks(client, task):
	files = client.list_bt(task)
	not_ready = []
	single_file = False
	if len(files) == 1 and files[0]['name'] == task['name']:
		single_file = True
	if 'files' in task:
		ordered_files = []
		indexed_files = dict((f['index'], f) for f in files)
		subs = []
		for index in task['files']:
			if index == '*':
				subs.extend([x['index'] for x in files])
			elif index.startswith('.'):
				subs.extend([x['index'] for x in files if x['name'].lower().endswith(index.lower())])
			else:
				subs.append(int(index))
		for index in subs:
			t = indexed_files[index]
			if t not in ordered_files:
				if t['status_text'] != 'completed':
					not_ready.append(t)
				else:
					ordered_files.append(t)
		files = ordered_files
	return files, not_ready, single_file


