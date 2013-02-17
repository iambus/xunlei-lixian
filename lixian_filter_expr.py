
__all__ = ['filter_expr']

import re

def filter_expr1(links, p, get_name):
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
		return filter(lambda x: re.search(p, get_name(x), re.I), links)

def filter_expr(links, expr, get_name):
	for p in expr.split('/'):
		links = filter_expr1(links, p, get_name)
	return links


