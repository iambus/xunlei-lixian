
__all__ = ['XunleiClient']

import urllib
import urllib2
import cookielib
import re
import time
import os.path
import json
from ast import literal_eval

USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko/20100101 Firefox/11.0'

def retry(f_or_arg, *args):
	#retry_sleeps = [1, 1, 1]
	retry_sleeps = [1, 2, 3, 5, 10, 20, 30, 60] + [60] * 60
	def decorator(f):
		def withretry(*args, **kwargs):
			for second in retry_sleeps:
				try:
					return f(*args, **kwargs)
				except:
					import traceback
					logger.debug("Exception happened. Retrying...")
					logger.debug(traceback.format_exc())
					time.sleep(second)
			raise
		return withretry
	if callable(f_or_arg) and not args:
		return decorator(f_or_arg)
	else:
		a = f_or_arg
		assert type(a) == int
		assert not args
		retry_sleeps = [1] * a
		return decorator

class Logger:
	def stdout(self, message):
		print message
	def info(self, message):
		print message
	def debug(self, message):
		pass
	def trace(self, message):
		pass

logger = Logger()

class WithAttrSnapshot:
	def __init__(self, object, **attrs):
		self.object = object
		self.attrs = attrs
	def __enter__(self):
		self.old_attrs = []
		for k in self.attrs:
			if hasattr(self.object, k):
				self.old_attrs.append((k, True, getattr(self.object, k)))
			else:
				self.old_attrs.append((k, False, None))
		for k in self.attrs:
			setattr(self.object, k, self.attrs[k])
	def __exit__(self, exc_type, exc_val, exc_tb):
		for k, has_old_attr, v in self.old_attrs:
			if has_old_attr:
				setattr(self.object, k, v)
			else:
				delattr(self.object, k)

class WithAttr:
	def __init__(self, object):
		self.object = object
	def __call__(self, **kwargs):
		return WithAttrSnapshot(self.object, **kwargs)
	def __getattr__(self, k):
		return lambda (v): WithAttrSnapshot(self.object, **{k:v})

# TODO: write unit test
class OnDemandTaskList:
	def __init__(self, fetch_page, page_size, limit):
		self.fetch_page = fetch_page
		if limit and page_size > limit:
			page_size = limit
		self.page_size = page_size
		self.limit = limit
		self.pages = {}
		self.max_task_number = None
		self.real_total_task_number = None
		self.total_pages = None

	def is_out_of_range(self, n):
		if self.limit:
			if n >= self.limit:
				return True
		if self.max_task_number:
			if n >= self.max_task_number:
				return True
		if self.real_total_task_number:
			if n >= self.real_total_task_number:
				return True

	def check_out_of_range(self, n):
		if self.is_out_of_range(n):
			raise IndexError('task index out of range')

	def is_out_of_page(self, page):
		raise NotImplementedError()

	def get_nth_task(self, n):
		self.check_out_of_range(n)
		page = n / self.page_size
		n_in_page = n - page * self.page_size
		return self.hit_page(page)[n_in_page]

	def touch(self):
		self.hit_page(0)

	def hit_page(self, page):
		if page in self.pages:
			return self.pages[page]
		info = self.fetch_page(page, self.page_size)
		tasks = info['tasks']
		if self.max_task_number is None:
			self.max_task_number = info['total_task_number']
			if self.limit and self.max_task_number > self.limit:
				self.max_task_number = self.limit
			self.total_pages = self.max_task_number / self.page_size
			if self.max_task_number % self.page_size != 0:
				self.total_pages += 1
			if self.max_task_number == 0:
				self.real_total_task_number = 0
		if page >= self.total_pages:
			tasks = []
		elif page == self.total_pages - 1:
			if self.page_size * page + len(tasks) > self.max_task_number:
				tasks = tasks[0:self.max_task_number - self.page_size * page]
			if len(tasks) > 0:
				self.real_total_task_number = self.page_size * page + len(tasks)
			else:
				self.max_task_number -= self.page_size
				self.total_pages -= 1
				if len(self.pages.get(page-1, [])) == self.page_size:
					self.real_total_task_number = self.max_task_number
		else:
			if len(tasks) == 0:
				self.max_task_number = self.page_size * page
				self.total_pages = page
				if len(self.pages.get(page-1, [])) == self.page_size:
					self.real_total_task_number = self.max_task_number
			elif len(tasks) < self.page_size:
				self.real_total_task_number = self.page_size * page + len(tasks)
				self.max_task_number = self.real_total_task_number
				self.total_pages = page
			else:
				pass
		for i, t in enumerate(tasks):
			t['#'] = self.page_size * page + i
		self.pages[page] = tasks
		return tasks

	def __getitem__(self, n):
		return self.get_nth_task(n)

	def __iter__(self):
		class Iterator:
			def __init__(self, container):
				self.container = container
				self.current = 0
			def next(self):
				self.container.touch()
				assert type(self.container.max_task_number) == int
				if self.container.real_total_task_number is None:
					if self.current < self.container.max_task_number:
						try:
							task = self.container[self.current]
						except IndexError:
							raise StopIteration()
					else:
						raise StopIteration()
				else:
					if self.current < self.container.real_total_task_number:
						task = self.container[self.current]
					else:
						raise StopIteration()
				self.current += 1
				return task
		return Iterator(self)

	def __len__(self):
		if self.real_total_task_number:
			return self.real_total_task_number
		self.touch()
		self.hit_page(self.total_pages-1)
		if self.real_total_task_number:
			return self.real_total_task_number
		count = 0
		for t in self:
			count += 1
		return count

class XunleiClient(object):
	default_page_size = 100
	default_bt_page_size = 9999
	def __init__(self, username=None, password=None, cookie_path=None, login=True, verification_code_reader=None):
		self.attr = WithAttr(self)

		self.username = username
		self.password = password
		self.cookie_path = cookie_path
		if cookie_path:
			self.cookiejar = cookielib.LWPCookieJar()
			if os.path.exists(cookie_path):
				self.load_cookies()
		else:
			self.cookiejar = cookielib.CookieJar()

		self.page_size = self.default_page_size
		self.bt_page_size = self.default_bt_page_size

		self.limit = None

		self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookiejar))
		self.verification_code_reader = verification_code_reader
		self.login_time = None
		if login:
			self.id = self.get_userid_or_none()
			if not self.id:
				self.login()
			self.id = self.get_userid()

	@property
	def page_size(self):
		return self._page_size
	@page_size.setter
	def page_size(self, size):
		self._page_size = size
		self.set_page_size(size)

	@retry
	def urlopen(self, url, **args):
		logger.debug(url)
#		import traceback
#		for line in traceback.format_stack():
#			print line.strip()
		if 'data' in args and type(args['data']) == dict:
			args['data'] = urlencode(args['data'])
		return self.opener.open(urllib2.Request(url, **args), timeout=60)

	def urlread1(self, url, **args):
		args.setdefault('headers', {})
		headers = args['headers']
		headers.setdefault('Accept-Encoding', 'gzip, deflate')
#		headers.setdefault('Referer', 'http://lixian.vip.xunlei.com/task.html')
		headers.setdefault('User-Agent', USER_AGENT)
#		headers.setdefault('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
#		headers.setdefault('Accept-Language', 'zh-cn,zh;q=0.7,en-us;q=0.3')
		response = self.urlopen(url, **args)
		data = response.read()
		if response.info().get('Content-Encoding') == 'gzip':
			data = ungzip(data)
		elif response.info().get('Content-Encoding') == 'deflate':
			data = undeflate(data)
		return data

	def urlread(self, url, **args):
		data = self.urlread1(url, **args)
		if self.is_session_timeout(data):
			logger.debug('session timed out')
			self.login()
			data = self.urlread1(url, **args)
		return data

	def load_cookies(self):
		self.cookiejar.load(self.cookie_path, ignore_discard=True, ignore_expires=True)

	def save_cookies(self):
		if self.cookie_path:
			self.cookiejar.save(self.cookie_path, ignore_discard=True)

	def get_cookie(self, domain, k):
		if self.has_cookie(domain, k):
			return self.cookiejar._cookies[domain]['/'][k].value

	def has_cookie(self, domain, k):
		return domain in self.cookiejar._cookies and k in self.cookiejar._cookies[domain]['/']

	def get_userid(self):
		if self.has_cookie('.xunlei.com', 'userid'):
			return self.get_cookie('.xunlei.com', 'userid')
		else:
			raise Exception('Probably login failed')

	def get_userid_or_none(self):
		return self.get_cookie('.xunlei.com', 'userid')

	def get_username(self):
		return self.get_cookie('.xunlei.com', 'usernewno')

	def get_gdriveid(self):
		return self.get_cookie('.vip.xunlei.com', 'gdriveid')

	def has_gdriveid(self):
		return self.has_cookie('.vip.xunlei.com', 'gdriveid')

	def get_referer(self):
		return 'http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s' % self.id

	def set_cookie(self, domain, k, v):
		c = cookielib.Cookie(version=0, name=k, value=v, port=None, port_specified=False, domain=domain, domain_specified=True, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={}, rfc2109=False)
		self.cookiejar.set_cookie(c)

	def del_cookie(self, domain, k):
		if self.has_cookie(domain, k):
			self.cookiejar.clear(domain=domain, path="/", name=k)

	def set_gdriveid(self, id):
		self.set_cookie('.vip.xunlei.com', 'gdriveid', id)

	def set_page_size(self, n):
		self.set_cookie('.vip.xunlei.com', 'pagenum', str(n))

	def get_cookie_header(self):
		def domain_header(domain):
			root = self.cookiejar._cookies[domain]['/']
			return '; '.join(k+'='+root[k].value for k in root)
		return domain_header('.xunlei.com') + '; ' + domain_header('.vip.xunlei.com')

	def check_device_id(self):
		if not self.has_cookie('.xunlei.com', 'deviceid'):
			device_url = 'http://login.xunlei.com/risk?cmd=report'
			xl_fp_raw = "P#etCxXneIMfMG3q###Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36###zh-CN###24###1200x1920###-480###true###true###true###undefined###function######Win32######Widevine Content Decryption Module::Enables Widevine licenses for playback of HTML audio/video content. (version: 1.4.8.893)::application/x-ppapi-widevine-cdm~;Chrome PDF Viewer::::application/pdf~pdf;Shockwave Flash::Shockwave Flash 23.0 r0::application/x-shockwave-flash~swf,application/futuresplash~spl;Native Client::::application/x-nacl~,application/x-pnacl~;Chrome PDF Viewer::Portable Document Format::application/x-google-chrome-pdf~pdf###22b4692f98f0d7a48ee37728981cd1c5###7u$v$2ZFjPZYMt3e"
			xl_fp = md5(xl_fp_raw)
			device_data = {'xl_fp_raw': xl_fp_raw, 'xl_fp': xl_fp}
			self.urlopen(device_url, data=device_data).read()
		if not self.has_cookie('.xunlei.com', '_x_t_'):
			self.set_cookie('.xunlei.com', '_x_t_', '0')

	def is_login_ok(self, html):
		return len(html) > 512

	def has_logged_in(self):
		id = self.get_userid_or_none()
		if not id:
			return False
		#print self.urlopen('http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s&st=0' % id).read().decode('utf-8')
		with self.attr(page_size=1):
			url = 'http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s&st=0' % id
			#url = 'http://dynamic.lixian.vip.xunlei.com/login?cachetime=%d' % current_timestamp()
			r = self.is_login_ok(self.urlread(url))
			return r

	def is_session_timeout(self, html):
		is_timeout = html == '''<script>document.cookie ="sessionid=; path=/; domain=xunlei.com"; document.cookie ="lx_sessionid=; path=/; domain=vip.xunlei.com";top.location='http://cloud.vip.xunlei.com/task.html?error=1'</script>''' or html == '''<script>document.cookie ="sessionid=; path=/; domain=xunlei.com"; document.cookie ="lsessionid=; path=/; domain=xunlei.com"; document.cookie ="lx_sessionid=; path=/; domain=vip.xunlei.com";top.location='http://cloud.vip.xunlei.com/task.html?error=2'</script>''' or html == '''<script>document.cookie ="sessionid=; path=/; domain=xunlei.com"; document.cookie ="lsessionid=; path=/; domain=xunlei.com"; document.cookie ="lx_sessionid=; path=/; domain=vip.xunlei.com";document.cookie ="lx_login=; path=/; domain=vip.xunlei.com";top.location='http://cloud.vip.xunlei.com/task.html?error=1'</script>'''
		if is_timeout:
			logger.trace(html)
			return True
		maybe_timeout = html == '''rebuild({"rtcode":-1,"list":[]})'''
		if maybe_timeout:
			if self.login_time and time.time() - self.login_time < 60 * 10: # 10 minutes
				return False
			else:
				logger.trace(html)
				return True
		return is_timeout

	def read_verification_code(self):
		if not self.verification_code_reader:
			raise NotImplementedError('Verification code required')
		else:
			verification_code_url = 'http://verify1.xunlei.com/image?t=MVA&cachetime=%s' % current_timestamp()
			image = self.urlopen(verification_code_url).read()
			return self.verification_code_reader(image)

	def login(self, username=None, password=None):
		username = self.username
		password = self.password
		if not username and self.has_cookie('.xunlei.com', 'usernewno'):
			username = self.get_username()
		if not username:
			# TODO: don't depend on lixian_config
			import lixian_config
			username = lixian_config.get_config('username')
#			if not username:
#				raise NotImplementedError('user is not logged in')
		if not password:
			raise NotImplementedError('user is not logged in')

		logger.debug('login')
		self.check_device_id()
		cachetime = current_timestamp()
		check_url = 'http://login.xunlei.com/check/?u=%s&business_type=108&v=101&cachetime=%d&' % (username, cachetime)
		login_page = self.urlopen(check_url).read()
		verification_code = self.get_cookie('.xunlei.com', 'check_result')[2:].upper()
		if not verification_code:
			verification_code = self.read_verification_code()
			if verification_code:
				verification_code = verification_code.upper()
		assert verification_code
		login_page = self.urlopen('https://login3.xunlei.com/sec2login/', headers={'User-Agent': USER_AGENT}, data={'u': username, 'p': password, 'verifycode': verification_code, 'login_enable': '0', 'business_type': '108', 'v': '101'})
		self.id = self.get_userid()
		with self.attr(page_size=1):
			login_page = self.urlopen('http://dynamic.lixian.vip.xunlei.com/login?cachetime=%d&from=0'%current_timestamp(), headers={ 'User-Agent': USER_AGENT}).read()
			#login_page = self.urlopen('http://dynamic.lixian.vip.xunlei.com/login?cachetime=%d&from=0'%current_timestamp()).read()
		if not self.is_login_ok(login_page):
			logger.trace(login_page)
			raise RuntimeError('login failed')
		self.save_cookies()
		self.login_time = time.time()

	def logout(self):
		logger.debug('logout')
		#session_id = self.get_cookie('.xunlei.com', 'sessionid')
		#timestamp = current_timestamp()
		#url = 'http://login.xunlei.com/unregister?sessionid=%s&cachetime=%s&noCacheIE=%s' % (session_id, timestamp, timestamp)
		#self.urlopen(url).read()
		#self.urlopen('http://dynamic.vip.xunlei.com/login/indexlogin_contr/logout/').read()
		ckeys = ["vip_isvip","lx_sessionid","vip_level","lx_login","dl_enable","in_xl","ucid","lixian_section"]
		ckeys1 = ["sessionid","usrname","nickname","usernewno","userid"]
		self.del_cookie('.vip.xunlei.com', 'gdriveid')
		for k in ckeys:
			self.set_cookie('.vip.xunlei.com', k, '')
		for k in ckeys1:
			self.set_cookie('.xunlei.com', k, '')
		self.save_cookies()
		self.login_time = None

	def to_page_url(self, type_id, page_index, page_size):
		# type_id: 1 for downloading, 2 for completed, 4 for downloading+completed+expired, 11 for deleted, 13 for expired
		if type_id == 0:
			type_id = 4
		page = page_index + 1
		p = 1 # XXX: what is it?
		# jsonp = 'jsonp%s' % current_timestamp()
		# url = 'http://dynamic.cloud.vip.xunlei.com/interface/showtask_unfresh?type_id=%s&page=%s&tasknum=%s&p=%s&interfrom=task&callback=%s' % (type_id, page, page_size, p, jsonp)
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/showtask_unfresh?type_id=%s&page=%s&tasknum=%s&p=%s&interfrom=task' % (type_id, page, page_size, p)
		return url

	@retry(10)
	def read_task_page_info_by_url(self, url):
		page = self.urlread(url).decode('utf-8', 'ignore')
		data = parse_json_response(page)
		if not self.has_gdriveid():
			gdriveid = data['info']['user']['cookie']
			self.set_gdriveid(gdriveid)
			self.save_cookies()
		# tasks = parse_json_tasks(data)
		tasks = [t for t in parse_json_tasks(data) if not t['expired']]
		for t in tasks:
			t['client'] = self
		# current_page = int(re.search(r'page=(\d+)', url).group(1))
		total_tasks = int(data['info']['total_num'])
		# assert total_pages >= data['global_new']['page'].count('<li><a')
		return {'tasks': tasks, 'total_task_number': total_tasks}

	def read_task_page_info_by_page_index(self, type_id, page_index, page_size):
		return self.read_task_page_info_by_url(self.to_page_url(type_id, page_index, page_size))

	def read_tasks(self, type_id=0):
		'''read one page'''
		page_size = self.page_size
		limit = self.limit
		if limit and limit < page_size:
			page_size = limit
		first_page = self.read_task_page_info_by_page_index(type_id, 0, page_size)
		tasks = first_page['tasks']
		for i, task in enumerate(tasks):
			task['#'] = i
		return tasks

	def read_all_tasks_immediately(self, type_id):
		'''read all pages'''
		all_tasks = []
		page_size = self.page_size
		limit = self.limit
		if limit and limit < page_size:
			page_size = limit
		first_page = self.read_task_page_info_by_page_index(type_id, 0, page_size)
		all_tasks.extend(first_page['tasks'])
		total_tasks = first_page['total_task_number']
		if limit and limit < total_tasks:
			total_tasks = limit
		total_pages = total_tasks / page_size
		if total_tasks % page_size != 0:
			total_pages += 1
		if total_pages == 0:
			total_pages = 1
		for page_index in range(1, total_pages):
			current_page = self.read_task_page_info_by_page_index(type_id, 0, page_size)
			all_tasks.extend(current_page['tasks'])
		if limit:
			all_tasks = all_tasks[0:limit]
		for i, task in enumerate(all_tasks):
			task['#'] = i
		return all_tasks

	def read_all_tasks_on_demand(self, type_id):
		'''read all pages, lazily'''
		fetch_page = lambda page_index, page_size: self.read_task_page_info_by_page_index(type_id, page_index, page_size)
		return OnDemandTaskList(fetch_page, self.page_size, self.limit)

	def read_all_tasks(self, type_id=0):
		'''read all pages'''
		return self.read_all_tasks_on_demand(type_id)

	def read_completed(self):
		'''read first page of completed tasks'''
		return self.read_tasks(2)

	def read_all_completed(self):
		'''read all pages of completed tasks'''
		return self.read_all_tasks(2)

	@retry(10)
	def read_categories(self):
#		url = 'http://dynamic.cloud.vip.xunlei.com/interface/menu_get?callback=jsonp%s&interfrom=task' % current_timestamp()
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/menu_get'
		html = self.urlread(url).decode('utf-8', 'ignore')
		result = parse_json_response(html)
		return dict((x['name'], int(x['id'])) for x in result['info'])

	def get_category_id(self, category):
		return self.read_categories()[category]

	def read_all_tasks_by_category(self, category):
		category_id = self.get_category_id(category)
		jsonp = 'jsonp%s' % current_timestamp()
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/show_class?callback=%s&type_id=%d' % (jsonp, category_id)
		html = self.urlread(url)
		response = json.loads(re.match(r'^%s\((.+)\)$' % jsonp, html).group(1))
		assert response['rtcode'] == '0', response['rtcode']
		info = response['info']
		tasks = map(convert_task, info['tasks'])
		for i, task in enumerate(tasks):
			task['client'] = self
			task['#'] = i
		return tasks

	def read_history_page_url(self, url):
		self.set_cookie('.vip.xunlei.com', 'lx_nf_all', urllib.quote('page_check_all=history&fltask_all_guoqi=1&class_check=0&page_check=task&fl_page_id=0&class_check_new=0&set_tab_status=11'))
		page = self.urlread(url).decode('utf-8', 'ignore')
		if not self.has_gdriveid():
			gdriveid = re.search(r'id="cok" value="([^"]+)"', page).group(1)
			self.set_gdriveid(gdriveid)
			self.save_cookies()
		tasks = parse_history(page)
		for t in tasks:
			t['client'] = self
		pginfo = re.search(r'<div class="pginfo">.*?</div>', page)
		match_next_page = re.search(r'<li class="next"><a href="([^"]+)">[^<>]*</a></li>', page)
		return tasks, match_next_page and 'http://dynamic.cloud.vip.xunlei.com'+match_next_page.group(1)

	def read_history_page(self, type=0, pg=None):
		if pg is None:
			url = 'http://dynamic.cloud.vip.xunlei.com/user_history?userid=%s&type=%d' % (self.id, type)
		else:
			url = 'http://dynamic.cloud.vip.xunlei.com/user_history?userid=%s&p=%d&type=%d' % (self.id, pg, type)
		return self.read_history_page_url(url)

	def read_history(self, type=0):
		'''read one page'''
		tasks = self.read_history_page(type)[0]
		for i, task in enumerate(tasks):
			task['#'] = i
		return tasks

	def read_all_history(self, type=0):
		'''read all pages of deleted/expired tasks'''
		all_tasks = []
		tasks, next_link = self.read_history_page(type)
		all_tasks.extend(tasks)
		while next_link:
			if self.limit and len(all_tasks) > self.limit:
				break
			tasks, next_link = self.read_history_page_url(next_link)
			all_tasks.extend(tasks)
		if self.limit:
			all_tasks = all_tasks[0:self.limit]
		for i, task in enumerate(all_tasks):
			task['#'] = i
		return all_tasks

	def read_deleted(self):
		return self.read_history()

	def read_all_deleted(self):
		return self.read_all_history()

	def read_expired(self):
		return self.read_history(1)

	def read_all_expired(self):
		return self.read_all_history(1)

	def list_bt(self, task):
		assert task['type'] == 'bt'
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/fill_bt_list?callback=fill_bt_list&tid=%s&infoid=%s&g_net=1&p=1&uid=%s&noCacheIE=%s' % (task['id'], task['bt_hash'], self.id, current_timestamp())
		with self.attr(page_size=self.bt_page_size):
			html = remove_bom(self.urlread(url)).decode('utf-8')
		sub_tasks = parse_bt_list(html)
		for t in sub_tasks:
			t['date'] = task['date']
		return sub_tasks

	def get_torrent_file_by_info_hash(self, info_hash):
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/get_torrent?userid=%s&infoid=%s' % (self.id, info_hash.upper())
		response = self.urlopen(url)
		torrent = response.read()
		if torrent == "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' /><script>alert('\xe5\xaf\xb9\xe4\xb8\x8d\xe8\xb5\xb7\xef\xbc\x8c\xe6\xb2\xa1\xe6\x9c\x89\xe6\x89\xbe\xe5\x88\xb0\xe5\xaf\xb9\xe5\xba\x94\xe7\x9a\x84\xe7\xa7\x8d\xe5\xad\x90\xe6\x96\x87\xe4\xbb\xb6!');</script>":
			raise Exception('Torrent file not found on xunlei cloud: '+info_hash)
		assert response.headers['content-type'] == 'application/octet-stream'
		return torrent

	def get_torrent_file(self, task):
		return self.get_torrent_file_by_info_hash(task['bt_hash'])

	def add_task(self, url):
		protocol = parse_url_protocol(url)
		assert protocol in ('ed2k', 'http', 'https', 'ftp', 'thunder', 'Flashget', 'qqdl', 'bt', 'magnet'), 'protocol "%s" is not suppoted' % protocol

		from lixian_url import url_unmask
		url = url_unmask(url)
		protocol = parse_url_protocol(url)
		assert protocol in ('ed2k', 'http', 'https', 'ftp', 'bt', 'magnet'), 'protocol "%s" is not suppoted' % protocol

		if protocol == 'bt':
			return self.add_torrent_task_by_info_hash(url[5:])
		elif protocol == 'magnet':
			return self.add_magnet_task(url)

		random = current_random()
		check_url = 'http://dynamic.cloud.vip.xunlei.com/interface/task_check?callback=queryCid&url=%s&random=%s&tcache=%s' % (urllib.quote(url), random, current_timestamp())
		js = self.urlread(check_url).decode('utf-8')
		qcid = re.match(r'^queryCid(\(.+\))\s*$', js).group(1)
		qcid = literal_eval(qcid)
		if len(qcid) == 8:
			cid, gcid, size_required, filename, goldbean_need, silverbean_need, is_full, random = qcid
		elif len(qcid) == 9:
			cid, gcid, size_required, filename, goldbean_need, silverbean_need, is_full, random, ext = qcid
		elif len(qcid) == 10:
			cid, gcid, size_required, some_key, filename, goldbean_need, silverbean_need, is_full, random, ext = qcid
		else:
			raise NotImplementedError(qcid)
		assert goldbean_need == 0
		assert silverbean_need == 0

		if url.startswith('http://') or url.startswith('ftp://'):
			task_type = 0
		elif url.startswith('ed2k://'):
			task_type = 2
		else:
			raise NotImplementedError()
		task_url = 'http://dynamic.cloud.vip.xunlei.com/interface/task_commit?'+urlencode(
		   {'callback': 'ret_task',
		    'uid': self.id,
		    'cid': cid,
		    'gcid': gcid,
		    'size': size_required,
		    'goldbean': goldbean_need,
		    'silverbean': silverbean_need,
		    't': filename,
		    'url': url,
			'type': task_type,
		    'o_page': 'task',
		    'o_taskid': '0',
		    })

		response = self.urlread(task_url)
		assert response == 'ret_task(Array)', response

	def add_batch_tasks(self, urls, old_task_ids=None):
		assert urls
		urls = list(urls)
		for url in urls:
			if parse_url_protocol(url) not in ('http', 'https', 'ftp', 'ed2k', 'bt', 'thunder', 'magnet'):
				raise NotImplementedError('Unsupported: '+url)
		urls = filter(lambda u: parse_url_protocol(u) in ('http', 'https', 'ftp', 'ed2k', 'thunder'), urls)
		if not urls:
			return
		#self.urlopen('http://dynamic.cloud.vip.xunlei.com/interface/batch_task_check', data={'url':'\r\n'.join(urls), 'random':current_random()})
		jsonp = 'jsonp%s' % current_timestamp()
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/batch_task_commit?callback=%s' % jsonp
		if old_task_ids:
			batch_old_taskid = ','.join(old_task_ids)
		else:
			batch_old_taskid = '0' + ',' * (len(urls) - 1) # XXX: what is it?
		data = {}
		for i in range(len(urls)):
			data['cid[%d]' % i] = ''
			data['url[%d]' % i] = urllib.quote(to_utf_8(urls[i])) # fix per request #98
		data['batch_old_taskid'] = batch_old_taskid
		data['verify_code'] = ''
		response = self.urlread(url, data=data)

		response_info = get_response_info(response, jsonp)
		code = response_info['process']
		while code == -12 or code == -11:
			verification_code = self.read_verification_code()
			assert verification_code
			data['verify_code'] = verification_code
			response = self.urlread(url, data=data)
			response_info = get_response_info(response, jsonp)
			code = response_info['process']
		if code == len(urls):
			return
		else:
			msg = response_info.get('msg')
			assert not msg, repr(msg.decode('utf-8'))
			assert code == len(urls), 'invalid response code: %s' % code

	def commit_torrent_task(self, data):
		jsonp = 'jsonp%s' % current_timestamp()
		commit_url = 'http://dynamic.cloud.vip.xunlei.com/interface/bt_task_commit?callback=%s' % jsonp
		def commit():
			response = self.urlread(commit_url, data=data)
			response_info = get_response_info(response, jsonp)
			code = response_info['progress']
			while code == -12 or code == -11:
				verification_code = self.read_verification_code()
				assert verification_code
				data['verify_code'] = verification_code
				response = self.urlread(commit_url, data=data)
				response_info = get_response_info(response, jsonp)
				code = response_info['progress']
			return response_info
		response_info = commit()
		if is_dirty_resource(response_info):
			data['btname'] = encode_dirty_name(data['btname'])
			response_info = commit()
		msg = response_info.get('msg')
		assert not msg, repr(msg)

	def add_torrent_task_by_content(self, content, path='attachment.torrent'):
		assert re.match(r'd\d+:', content), 'Probably not a valid content file [%s...]' % repr(content[:17])
		upload_url = 'http://dynamic.cloud.vip.xunlei.com/interface/torrent_upload'
		content_type, body = encode_multipart_formdata([], [('filepath', path, content)])
		response = self.urlread(upload_url, data=body, headers={'Content-Type': content_type}).decode('utf-8')

		upload_success = re.search(r'<script>document\.domain="xunlei\.com";var btResult =(\{.*\});</script>', response, flags=re.S)
		if upload_success:
			bt = json.loads(upload_success.group(1))
			bt_hash = bt['infoid']
			bt_name = bt['ftitle']
			bt_size = bt['btsize']
			data = {'uid':self.id, 'btname':bt_name, 'cid':bt_hash, 'tsize':bt_size,
					'findex':''.join(f['id']+'_' for f in bt['filelist']),
					'size':''.join(f['subsize']+'_' for f in bt['filelist']),
					'from':'0'}
			self.commit_torrent_task(data)
			return bt_hash
		already_exists = re.search(r"parent\.edit_bt_list\((\{.*\}),'','0'\)", response, flags=re.S)
		if already_exists:
			bt = json.loads(already_exists.group(1))
			bt_hash = bt['infoid']
			return bt_hash
		raise NotImplementedError(response)

	def add_torrent_task(self, path):
		with open(path, 'rb') as x:
			return self.add_torrent_task_by_content(x.read(), os.path.basename(path))

	def add_torrent_task_by_info_hash(self, sha1, old_task_id=None):
		return self.add_magnet_task('magnet:?xt=urn:btih:' + sha1.upper())

	def add_magnet_task(self, link):
		return self.add_torrent_task_by_link(link)

	def add_torrent_task_by_link(self, link, old_task_id=None):
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/url_query?callback=queryUrl&u=%s&random=%s' % (urllib.quote(link), current_timestamp())
		response = self.urlread(url)
		success = re.search(r'queryUrl(\(1,.*\))\s*$', response, flags=re.S) # XXX: sometimes it returns queryUrl(0,...)?
		if not success:
			already_exists = re.search(r"queryUrl\(-1,'([^']{40})", response, flags=re.S)
			if already_exists:
				return already_exists.group(1)
			raise NotImplementedError(repr(response))
		args = success.group(1).decode('utf-8')
		args = literal_eval(args.replace('new Array', ''))
		_, cid, tsize, btname, _, names, sizes_, sizes, _, types, findexes, _, timestamp, _ = args
		def toList(x):
			if type(x) in (list, tuple):
				return x
			else:
				return [x]
		data = {'uid':self.id, 'btname':btname, 'cid':cid, 'tsize':tsize,
				'findex':''.join(x+'_' for x in toList(findexes)),
				'size':''.join(x+'_' for x in toList(sizes)),
				'from':'0'}
		if old_task_id:
			data['o_taskid'] = old_task_id
			data['o_page'] = 'history'
		self.commit_torrent_task(data)
		return cid

	def readd_all_expired_tasks(self):
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/delay_once?callback=anything'
		response = self.urlread(url)

	def delete_tasks_by_id(self, ids):
		jsonp = 'jsonp%s' % current_timestamp()
		data = {'taskids': ','.join(ids)+',', 'databases': '0,'}
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/task_delete?callback=%s&type=%s&noCacheIE=%s' % (jsonp, 2, current_timestamp()) # XXX: what is 'type'?
		response = self.urlread(url, data=data)
		response = remove_bom(response)
		assert_response(response, jsonp, '{"result":1,"type":2}')

	def delete_task_by_id(self, id):
		self.delete_tasks_by_id([id])

	def delete_task(self, task):
		self.delete_task_by_id(task['id'])

	def delete_tasks(self, tasks):
		self.delete_tasks_by_id([t['id'] for t in tasks])

	def pause_tasks_by_id(self, ids):
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/task_pause?tid=%s&uid=%s&noCacheIE=%s' % (','.join(ids)+',', self.id, current_timestamp())
		assert self.urlread(url) == 'pause_task_resp()'

	def pause_task_by_id(self, id):
		self.pause_tasks_by_id([id])

	def pause_task(self, task):
		self.pause_task_by_id(task['id'])

	def pause_tasks(self, tasks):
		self.pause_tasks_by_id(t['id'] for t in tasks)

	def restart_tasks(self, tasks):
		jsonp = 'jsonp%s' % current_timestamp()
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/redownload?callback=%s' % jsonp
		form = []
		for task in tasks:
			assert task['type'] in ('ed2k', 'http', 'https', 'ftp', 'https', 'bt'), "'%s' is not tested" % task['type']
			data = {'id[]': task['id'],
					'cid[]': '', # XXX: should I set this?
					'url[]': task['original_url'],
					'download_status[]': task['status']}
			if task['type'] == 'ed2k':
				data['taskname[]'] = task['name'].encode('utf-8') # XXX: shouldn't I set this for other task types?
			form.append(urlencode(data))
		form.append(urlencode({'type':1}))
		data = '&'.join(form)
		response = self.urlread(url, data=data)
		assert_response(response, jsonp)

	def rename_task(self, task, new_name):
		assert type(new_name) == unicode
		url = 'http://dynamic.cloud.vip.xunlei.com/interface/rename'
		taskid = task['id']
		bt = '1' if task['type'] == 'bt' else '0'
		url = url+'?'+urlencode({'taskid':taskid, 'bt':bt, 'filename':new_name.encode('utf-8')})
		response = self.urlread(url)
		assert '"result":0' in response, response

	def restart_task(self, task):
		self.restart_tasks([task])

	def get_task_by_id(self, id):
		tasks = self.read_all_tasks(0)
		for x in tasks:
			if x['id'] == id:
				return x
		raise Exception('No task found for id '+id)


def current_timestamp():
	return int(time.time()*1000)

def current_random():
	from random import randint
	return '%s%06d.%s' % (current_timestamp(), randint(0, 999999), randint(100000000, 9999999999))

def convert_task(data):
	expired = {'0':False, '4': True}[data['flag']]
	assert re.match(r'[^:]+', data['url']), 'Invalid URL in: ' + repr(data)
	task = {'id': data['id'],
			'type': re.match(r'[^:]+', data['url']).group().lower(),
			'name': decode_dirty_name(unescape_html(data['taskname'])),
			'status': int(data['download_status']),
			'status_text': {'0':'waiting', '1':'downloading', '2':'completed', '3':'failed', '5':'pending'}[data['download_status']],
			'expired': expired,
			'size': int(data['ysfilesize']),
			'original_url': unescape_html(data['url']),
			'xunlei_url': data['lixian_url'] or None,
			'bt_hash': data['cid'],
			'dcid': data['cid'],
			'gcid': data['gcid'],
			'date': data['dt_committed'][:10].replace('-', '.'),
			'progress': '%s%%' % data['progress'],
			'speed': '%s' % data['speed'],
			}
	return task

def parse_json_response(html):
	m = re.match(ur'^\ufeff?rebuild\((\{.*\})\)$', html)
	if not m:
		logger.trace(html)
		raise RuntimeError('Invalid response')
	return json.loads(m.group(1))

def parse_json_tasks(result):
	tasks = result['info']['tasks']
	return map(convert_task, tasks)

def parse_task(html):
	inputs = re.findall(r'<input[^<>]+/>', html)
	def parse_attrs(html):
		return dict((k, v1 or v2) for k, v1, v2 in re.findall(r'''\b(\w+)=(?:'([^']*)'|"([^"]*)")''', html))
	info = dict((x['id'], unescape_html(x['value'])) for x in map(parse_attrs, inputs))
	mini_info = {}
	mini_map = {}
	#mini_info = dict((re.sub(r'\d+$', '', k), info[k]) for k in info)
	for k in info:
		mini_key = re.sub(r'\d+$', '', k)
		mini_info[mini_key] = info[k]
		mini_map[mini_key] = k
	taskid = mini_map['taskname'][8:]
	url = mini_info['f_url']
	task_type = re.match(r'[^:]+', url).group().lower()
	task = {'id': taskid,
	        'type': task_type,
	        'name': mini_info['taskname'],
	        'status': int(mini_info['d_status']),
	        'status_text': {'0':'waiting', '1':'downloading', '2':'completed', '3':'failed', '5':'pending'}[mini_info['d_status']],
	        'size': int(mini_info.get('ysfilesize', 0)),
	        'original_url': mini_info['f_url'],
	        'xunlei_url': mini_info.get('dl_url', None),
	        'bt_hash': mini_info['dcid'],
	        'dcid': mini_info['dcid'],
	        'gcid': parse_gcid(mini_info.get('dl_url', None)),
	        }

	m = re.search(r'<em class="loadnum"[^<>]*>([^<>]*)</em>', html)
	task['progress'] = m and m.group(1) or ''
	m = re.search(r'<em [^<>]*id="speed\d+">([^<>]*)</em>', html)
	task['speed'] = m and m.group(1).replace('&nbsp;', '') or ''
	m = re.search(r'<span class="c_addtime">([^<>]*)</span>', html)
	task['date'] = m and m.group(1) or ''

	return task

def parse_history(html):
	rwbox = re.search(r'<div class="rwbox" id="rowbox_list".*?<!--rwbox-->', html, re.S).group()
	rw_lists = re.findall(r'<div class="rw_list".*?<input id="d_tasktype\d+"[^<>]*/>', rwbox, re.S)
	return map(parse_task, rw_lists)

def parse_bt_list(js):
	result = json.loads(re.match(r'^fill_bt_list\((.+)\)\s*$', js).group(1))['Result']
	files = []
	for record in result['Record']:
		files.append({
			'id': record['taskid'],
			'index': record['id'],
			'type': 'bt',
			'name': record['title'], # TODO: support folder
			'status': int(record['download_status']),
			'status_text': {'0':'waiting', '1':'downloading', '2':'completed', '3':'failed', '5':'pending'}[record['download_status']],
			'size': int(record['filesize']),
			'original_url': record['url'],
			'xunlei_url': record['downurl'],
			'dcid': record['cid'],
			'gcid': parse_gcid(record['downurl']),
			'speed': '',
			'progress': '%s%%' % record['percent'],
			'date': '',
			})
	return files

def parse_gcid(url):
	if not url:
		return
	m = re.search(r'&g=([A-F0-9]{40})&', url)
	if not m:
		return
	return m.group(1)

def urlencode(x):
	def unif8(u):
		if type(u) == unicode:
			u = u.encode('utf-8')
		return u
	return urllib.urlencode([(unif8(k), unif8(v)) for k, v in x.items()])

def encode_multipart_formdata(fields, files):
	#http://code.activestate.com/recipes/146306/
	"""
	fields is a sequence of (name, value) elements for regular form fields.
	files is a sequence of (name, filename, value) elements for data to be uploaded as files
	Return (content_type, body) ready for httplib.HTTP instance
	"""
	BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
	CRLF = '\r\n'
	L = []
	for (key, value) in fields:
		L.append('--' + BOUNDARY)
		L.append('Content-Disposition: form-data; name="%s"' % key)
		L.append('')
		L.append(value)
	for (key, filename, value) in files:
		L.append('--' + BOUNDARY)
		L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
		L.append('Content-Type: %s' % get_content_type(filename))
		L.append('')
		L.append(value)
	L.append('--' + BOUNDARY + '--')
	L.append('')
	body = CRLF.join(L)
	content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
	return content_type, body

def get_content_type(filename):
	import mimetypes
	return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def assert_default_page(response, id):
	#assert response == "<script>top.location='http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s&st=0'</script>" % id
	assert re.match(r"^<script>top\.location='http://dynamic\.cloud\.vip\.xunlei\.com/user_task\?userid=%s&st=0(&cache=\d+)?'</script>$" % id, response), response

def remove_bom(response):
	if response.startswith('\xef\xbb\xbf'):
		response = response[3:]
	return response

def assert_response(response, jsonp, value=1):
	response = remove_bom(response)
	assert response == '%s(%s)' % (jsonp, value), repr(response)

def get_response_info(response, jsonp):
	response = remove_bom(response)
	m = re.match(r'^%s\((.+)\)$' % jsonp, response)
	assert m, 'invalid jsonp response: %s' % response
	logger.trace('get_response_info')
	logger.trace(response)
	parameter = m.group(1)
	m = re.match(r"^\{process:(-?\d+),msg:'(.*)'\}$", parameter)
	if m:
		return {'process': int(m.group(1)), 'msg': m.group(2)}
	return json.loads(parameter)

def parse_url_protocol(url):
	m = re.match(r'([^:]+)://', url)
	if m:
		return m.group(1)
	elif url.startswith('magnet:'):
		return 'magnet'
	else:
		return url

def unescape_html(html):
	import xml.sax.saxutils
	return xml.sax.saxutils.unescape(html)

def to_utf_8(s):
	if type(s) == unicode:
		return s.encode('utf-8')
	else:
		return s

def md5(s):
	import hashlib
	return hashlib.md5(s).hexdigest().lower()

def ungzip(s):
	from StringIO import StringIO
	import gzip
	buffer = StringIO(s)
	f = gzip.GzipFile(fileobj=buffer)
	return f.read()

def undeflate(s):
	import zlib
	return zlib.decompress(s, -zlib.MAX_WBITS)

def is_dirty_resource(response_info):
	return response_info['progress'] == 2 and response_info.get('rtcode') == '76' and response_info.get('msg') == u"\u6587\u4ef6\u540d\u4e2d\u5305\u542b\u8fdd\u89c4\u5185\u5bb9\uff0c\u65e0\u6cd5\u6dfb\u52a0\u5230\u79bb\u7ebf\u7a7a\u95f4[0976]"

def encode_dirty_name(x):
	import base64
	try:
		return unicode('[base64]' + base64.encodestring(x.encode('utf-8')).replace('\n', ''))
	except:
		return x

def decode_dirty_name(x):
	import base64
	try:
		if x.startswith('[base64]'):
			return base64.decodestring(x[len('[base64]'):]).decode('utf-8')
		else:
			return x
	except:
		return x

