
import re

page_parsers = {}

def register_parser(site, extend_link):
	page_parsers[site] = extend_link

def load_parsers():
	import os
	import os.path
	parser_dir = os.path.dirname(__file__)
	parsers = os.listdir(parser_dir)
	parsers = [re.sub(r'\.py$', '', p) for p in parsers if p.endswith('.py') and not p.startswith('_')]
	for p in parsers:
		__import__('lixian_plugins.parsers.' + p)


def in_site(url, site):
	if url.startswith(site):
		return True
	if '*' in site:
		import fnmatch
		p = fnmatch.translate(site)
		return re.match(p, url)

def find_parser(link):
	for p in page_parsers:
		if in_site(link, p):
			return page_parsers[p]


def to_name(x):
	if type(x) == dict:
		return x['name']
	else:
		return x

def to_url(x):
	if type(x) == dict:
		return x['url']
	else:
		return x

def filter_links1(links, p):
	if re.match(r'^\[[^][]+\]$', p):
		indexes = []
		for p in re.split(r'\s*,\s*', p[1:-1]):
			if re.match(r'^\d+$', p):
				i = int(p)
				if i not in indexes:
					indexes.append(i)
			elif '-' in p:
				start, end = p.split('-')
				if not start:
					start = 0
				if not end:
					end = len(links) - 1
				for i in range(int(start), int(end)+1):
					if i not in indexes:
						indexes.append(i)
			else:
				raise NotImplementedError(p)
		return [links[x] for x in indexes if 0 <= x < len(links)]
	else:
		return filter(lambda x: re.search(p, to_name(x), re.I), links)

def filter_links(links, patterns):
	for p in patterns:
		links = filter_links1(links, p)
	return links

def parse_pattern(link):
	m = re.search(r'[^:]//', link)
	if m:
		u = link[:m.start()+1]
		p = link[m.start()+3:]
		assert '//' not in p, link
		if p.endswith('/'):
			u += '/'
			p = p[:-1]
		return u, p.split('/')


def try_to_extend_link(link):
	parser = find_parser(link)
	if parser:
		x = parse_pattern(link)
		if x:
			links = parser(x[0])
			return filter_links(links, x[1])
		else:
			return parser(link)

def extend_link(link):
	return try_to_extend_link(link) or [link]

def extend_links_rich(links):
	return sum(map(extend_link, links), [])

def extend_links(links):
	return map(to_url, extend_links_rich(links))

def extend_links_name(links):
	return map(to_name, extend_links_rich(links))

