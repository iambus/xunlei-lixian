
import urllib2
import re


def simplecd_links(url):
	m = re.match(r'(http://(?:www\.)?simplecd\.\w+/)(id|entry)/', url)
	assert m, url
	site = m.group(1)
	html = urllib2.urlopen(url).read()
	ids = re.findall(r'value="(\w+)"\s+name="selectemule"', html)
	form = '&'.join('rid=' + id for id in ids)
	q = 'mode=copy&' + form
	html = urllib2.urlopen(site + 'download/?' + q).read()
	table = re.search(r'<table id="showall" .*?</table>', html, flags=re.S).group()
	links = re.findall(r'ed2k://[^\s<>]+', table)
	return links

def extend_link(url):
	links = simplecd_links(url)
	from lixian_hash_ed2k import parse_ed2k_file
	return [{'url':x, 'name':parse_ed2k_file(x)} for x in links]

