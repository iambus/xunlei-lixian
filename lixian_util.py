
__all__ = []

import re

def format_1d(n):
	return re.sub(r'\.0*$', '', '%.1f' % n)

def format_size(n):
	if n < 1000:
		return '%sB' % n
	elif n < 1000**2:
		return '%sK' % format_1d(n/1000.)
	elif n < 1000**3:
		return '%sM' % format_1d(n/1000.**2)
	elif n < 1000**4:
		return '%sG' % format_1d(n/1000.**3)


def parse_size(size):
	size = str(size)
	if re.match('^\d+$', size):
		return int(size)
	m = re.match(r'^(\d+(?:\.\d+)?)(K|M|G)B?$', size, flags=re.I)
	if not m:
		raise Exception("Invalid size format: %s" % size)
	return int(float(m.group(1)) * {'K': 1000, 'M': 1000*1000, 'G': 1000*1000*1000}[m.group(2).upper()])


