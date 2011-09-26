

import urllib
import urllib2
import cookielib
import re
import time
import os.path


def get_time():
	return int(time.time()*1000)

def parse_link(html):
	inputs = re.findall(r'<input[^<>]+/>', html)
	def parse_attrs(html):
		return dict((k, v1 or v2) for k, v1, v2 in re.findall(r'''\b(\w+)=(?:'([^']*)'|"([^"]*)")''', html))
	info = dict((x['id'], x['value']) for x in map(parse_attrs, inputs))
	mini_info = {}
	mini_map = {}
	#mini_info = dict((re.sub(r'\d+$', '', k), info[k]) for k in info)
	for k in info:
		mini_key = re.sub(r'\d+$', '', k)
		mini_info[mini_key] = info[k]
		mini_map[mini_key] = k
	taskid = mini_map['durl'][4:]
	url = mini_info['f_url']
	task_type = re.match(r'[^:]+', url).group()
	task = {'id': taskid,
			'type': task_type,
			'name': mini_info['durl'],
			'status': int(mini_info['d_status']),
			'status_text': {'0':'waiting', '1':'downloading', '2':'completed', '3':'failed'}[mini_info['d_status']],
			'size': int(mini_info['ysfilesize']),
			'original_url': mini_info['f_url'],
			'xunlei_url': mini_info['dl_url'],
			'bt_hash': mini_info['dcid'],
			}
	# XXX: should I return bt files?
	return task

def parse_links(html):
	rwbox = re.search(r'<div class="rwbox".*<!--rwbox-->', html, re.S).group()
	rw_lists = re.findall(r'<div class="rw_list".*?<!-- rw_list -->', rwbox, re.S)
	return map(parse_link, rw_lists)

def parse_bt_list(js):
	import json
	result = json.loads(re.match(r'^fill_bt_list\((.+)\)\s*$', js).group(1))['Result']
	files = []
	for record in result['Record']:
		files.append({
			'id': record['taskid'],
			'type': 'bt',
			'name': record['title'], # TODO: support folder
			'status': int(record['download_status']),
			'status_text': {'0':'waiting', '1':'downloading', '2':'completed', '3':'failed'}[record['download_status']],
			'size': record['filesize'],
			'original_url': record['url'],
			'xunlei_url': record['downurl'],
			})
	return files

class XunleiClient:
	def __init__(self, username=None, password=None, cookie_path=None):
		self.cookie_path = cookie_path
		if cookie_path:
			self.cookiejar = cookielib.LWPCookieJar()
			if os.path.exists(cookie_path):
				self.load_cookies()
			else:
				self.save_cookies()
		else:
			self.cookiejar = cookielib.CookieJar()
		self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookiejar))
		#self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookiejar),  urllib2.ProxyHandler({"http" : 'http://localhost:9008'}))
		if not self.has_logged_in():
			if not username:
				raise NotImplementedError()
			self.login(username, password)
		else:
			self.id = self.get_userid()

	def urlopen(self, url, **args):
		print url
		return self.opener.open(urllib2.Request(url, **args))

	def load_cookies(self):
		self.cookiejar.load(self.cookie_path, ignore_discard=True, ignore_expires=True)

	def save_cookies(self):
		if self.cookie_path:
			self.cookiejar.save(self.cookie_path, ignore_discard=True)

	def get_cookie(self, domain, k):
		return self.cookiejar._cookies[domain]['/'][k].value

	def has_cookie(self, domain, k):
		return k in self.cookiejar._cookies[domain]['/']

	def get_userid(self):
		return self.get_cookie('.xunlei.com', 'userid')

	def get_gdriveid(self):
		return self.get_cookie('.vip.xunlei.com', 'gdriveid')

	def has_gdriveid(self):
		return self.has_cookie('.vip.xunlei.com', 'gdriveid')

	def get_referer(self):
		return 'http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s' % self.id

	def set_cookie(self, domain, k, v):
		c = cookielib.Cookie(version=0, name=k, value=v, port=None, port_specified=False, domain=domain, domain_specified=True, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={}, rfc2109=False)
		self.cookiejar.set_cookie(c)

	def set_gdriveid(self, id):
		self.set_cookie('.vip.xunlei.com', 'gdriveid', id)

	def set_page_size(self, n):
		self.set_cookie('.vip.xunlei.com', 'pagenum', str(n))

	def get_cookie_header(self):
		def domain_header(domain):
			root = self.cookiejar._cookies[domain]['/']
			return '; '.join(k+'='+root[k].value for k in root)
		return  domain_header('.xunlei.com') + '; ' + domain_header('.vip.xunlei.com')

	def has_logged_in(self):
		return len(self.urlopen('http://dynamic.lixian.vip.xunlei.com/login?cachetime=%d'%int(time.time()*1000)).read()) > 512

	def login(self, username, password):
		cachetime = int(time.time()*1000)
		check_url = 'http://login.xunlei.com/check?u=%s&cachetime=%d' % (username, cachetime)
		login_page = self.urlopen(check_url).read()
		verifycode = self.get_cookie('.xunlei.com', 'check_result')[2:].upper()
		def md5(s):
			import hashlib
			return hashlib.md5(s).hexdigest().lower()
		if not re.match(r'^[0-9a-f]{32}$', username):
			password = md5(md5(password))
		password = md5(password+verifycode)
		login_page = self.urlopen('http://login.xunlei.com/sec2login/', data=urllib.urlencode({'u': username, 'p': password, 'verifycode': verifycode}))
		self.id = self.get_userid()
		login_page = self.urlopen('http://dynamic.lixian.vip.xunlei.com/login?cachetime=%d&from=0'%int(time.time()*1000))
		self.save_cookies()

	def list_bt(self, task):
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/fill_bt_list?callback=fill_bt_list&tid=%s&infoid=%s&g_net=1&p=1&uid=%s&noCacheIE=%s' % (task['id'], task['bt_hash'], self.id, get_time())
		html = self.urlopen(url).read().decode('utf-8')
		return parse_bt_list(html)

	def read_task_page_url(self, url):
		req = self.urlopen(url)
		page = req.read().decode('utf-8')
		if not self.has_gdriveid():
			gdriveid = re.search(r'id="cok" value="([^"]+)"', page).group(1)
			self.set_gdriveid(gdriveid)
		links = parse_links(page)
		pginfo = re.search(r'<div class="pginfo">.*?</div>', page)
		match_next_page = re.search(r'<li class="next"><a href="([^"]+)">[^<>]*</a></li>', page)
		return links, match_next_page and 'http://dynamic.cloud.vip.xunlei.com'+match_next_page.group(1)

	def read_task_page(self, st, pg=None):
		if pg is None:
			url = 'http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s&st=%d' % (self.id, st)
		else:
			url = 'http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s&st=%d&p=%d' % (self.id, st, pg)
		return self.read_task_page_url(url)

	def read_tasks(self, st):
		return self.read_task_page(st)[0]

	def read_all_tasks(self, st):
		all_links = []
		links, next_link = self.read_task_page(st)
		all_links.extend(links)
		while next_link:
			links, next_link = self.read_task_page_url(next_link)
			all_links.extend(links)
		return all_links

	def read_completed(self):
		return self.read_tasks(2)



