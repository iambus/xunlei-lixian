
import re
import urllib2

from lixian_encoding import default_encoding

def link_normalize(url):
	from lixian_url import url_unmask, normalize_unicode_link
	from lixian_url import url_unmask, normalize_unicode_link
	url = url_unmask(url)
	if url.startswith('magnet:'):
		return 'bt://'+lixian_hash_bt.magnet_to_infohash(url).encode('hex')
	elif url.startswith('ed2k://'):
		return lixian_hash_ed2k.parse_ed2k_link(url)
	elif url.startswith('bt://'):
		return url.lower()
	elif url.startswith('http://') or url.startswith('ftp://'):
		return normalize_unicode_link(url)
	return url

def link_equals(x1, x2):
	return link_normalize(x1) == link_normalize(x2)

def link_in(url, links):
	for link in links:
		if link_equals(url, link):
			return True

def find_torrents_task_to_download(client, links):
	tasks = client.read_all_tasks()
	hashes = set(t['bt_hash'].lower() for t in tasks if t['type'] == 'bt')
	link_hashes = []
	for link in links:
		if re.match(r'^(?:bt://)?([a-fA-F0-9]{40})$', link):
			info_hash = link[-40:].lower()
			if info_hash not in hashes:
				print 'Adding bt task', link
				client.add_torrent_task_by_info_hash(info_hash)
			link_hashes.append(info_hash)
		elif re.match(r'http://', link):
			print 'Downloading torrent file from', link
			torrent = urllib2.urlopen(link, timeout=60).read()
			assert torrent.startswith('d8:announce') or torrent.startswith('d13:announce-list'), 'Probably not a valid torrent file [%s...]' % repr(torrent[:17])
			info_hash = lixian_hash_bt.info_hash_from_content(torrent)
			if info_hash not in hashes:
				print 'Adding bt task', link
				client.add_torrent_task_by_content(torrent, os.path.basename(link))
			link_hashes.append(info_hash)
		elif os.path.exists(link):
			with open(link, 'rb') as stream:
				torrent = stream.read()
			assert torrent.startswith('d8:announce') or torrent.startswith('d13:announce-list'), 'Probably not a valid torrent file [%s...]' % repr(torrent[:17])
			info_hash = lixian_hash_bt.info_hash_from_content(torrent)
			if info_hash not in hashes:
				print 'Adding bt task', link
				client.add_torrent_task_by_content(torrent, os.path.basename(link))
			link_hashes.append(info_hash)
		else:
			raise NotImplementedError('Unknown torrent '+link)
	all_tasks = client.read_all_tasks()
	tasks = []
	for h in link_hashes:
		for t in all_tasks:
			if t['bt_hash'].lower() == h.lower():
				tasks.append(t)
				break
		else:
			raise NotImplementedError('not task found')
	return tasks

def find_tasks_to_download(client, args):
	links = []
	links.extend(args)
	if args.input:
		links.extend(line.strip() for line in fileinput.input(args.input) if line.strip())
	if args.torrent:
		return find_torrents_task_to_download(client, links)
	if args.search or any(re.match(r'^#?\d+(/[-.\w\[\],\s]+|-\d+)?$', x) for x in args):
		return search_tasks(client, args, check='check_none')
	all_tasks = client.read_all_tasks()
	to_add = set(links)
	for t in all_tasks:
		for x in to_add:
			if link_equals(t['original_url'], x):
				to_add.remove(x)
				break
	if to_add:
		print 'Adding below tasks:'
		for link in links:
			if link in to_add:
				print link
		client.add_batch_tasks(map(to_utf_8, to_add))
		for link in to_add:
			# add_batch_tasks doesn't work for bt task, add bt task one by one...
			if link.startswith('bt://') or link.startswith('magnet:'):
				client.add_task(link)
		all_tasks = client.read_all_tasks()
	tasks = []
	for link in links:
		for task in all_tasks:
			if link_equals(link, task['original_url']):
				tasks.append(task)
				break
		else:
			raise NotImplementedError('task not found, wired: '+link)
	return tasks

def merge_bt_sub_tasks(tasks):
	result_tasks = []
	task_mapping = {}
	for task in tasks:
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
	return result_tasks

def filter_tasks(tasks, k, v):
	if k == 'id':
		task_id, sub_id = re.match(r'^(#?\d+)(?:/([-.\w\[\],\s]+))?$', v).groups()
		if task_id.startswith('#'):
			task_id = int(task_id[1:])
			matched = [tasks[task_id]] if task_id < len(tasks) else []
		else:
			matched = filter(lambda t: t['id'] == task_id, tasks)
		if matched:
			assert len(matched) == 1
			task = matched[0]
			if sub_id:
				assert task['type'] == 'bt', 'task %s is not a bt task' % task['name'].encode(default_encoding)
				matched = []
				if re.match(r'\[.*\]', sub_id):
					for sub_id in re.split(r'\s*,\s*', sub_id[1:-1]):
						assert re.match(r'^\d+(-\d+)?|\.\w+$', sub_id), sub_id
						if sub_id.startswith('.'):
							t = dict(task)
							t['index'] = sub_id
							matched.append(t)
						elif '-' in sub_id:
							start, end = sub_id.split('-')
							for i in range(int(start), int(end)+1):
								t = dict(task)
								t['index'] = str(i)
								matched.append(t)
						else:
							assert re.match(r'^\d+$', sub_id), sub_id
							t = dict(task)
							t['index'] = sub_id
							matched.append(t)
				elif re.match(r'^\.\w+$', sub_id):
					t = dict(task)
					t['index'] = sub_id
					matched.append(t)
				else:
					assert re.match(r'^\d+$', sub_id), sub_id
					t = dict(task)
					t['index'] = sub_id
					matched.append(t)
			else:
				matched = [task]
	elif k == 'name':
		matched = filter(lambda t: t[k].lower().find(v.lower()) != -1 or t['date'] == v, tasks) # XXX: a dirty trick: support search by date
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
		if args.search:
			matched = filter_tasks(tasks, 'name', x.decode(default_encoding))
		else:
			if re.match(r'^#?\d+(/[-.\w\[\],\s]+)?$', x):
				matched = filter_tasks(tasks, 'id', x)
				if not matched:
					matched = filter_tasks(tasks, 'name', x.decode(default_encoding))
			elif re.match(r'^#\d+-\d+$', x):
				begin, end = x[1:].split('-')
				begin = int(begin)
				end = int(end)
				if begin > end or begin >= len(tasks):
					matched = []
				elif end >= len(tasks):
					matched = tasks[begin:]
				else:
					matched = tasks[begin:end+1]
			#elif re.match(r'^\d{4}\.\d{2}\.\d{2}$', x):
			#	matched = filter_tasks(tasks, 'date', x)
			elif re.match(r'\w+://', x) or x.startswith('magnet:'):
				matched = filter_tasks(tasks, 'original_url', to_utf_8(x))
			else:
				matched = filter_tasks(tasks, 'name', x.decode(default_encoding))
		if check:
			if not matched:
				raise RuntimeError('Not task found for '+x)
			if check != 'check_none' and (not args.all) and len(matched) > 1:
				raise RuntimeError('Too many tasks found for '+x)
		found.extend(matched)
	return found

