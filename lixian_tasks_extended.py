
sites = {
'http://kuai.xunlei.com/d/':'lixian_kuai',
'http://www.verycd.com/topics/':'lixian_verycd',
}

def extend_link(link):
	for p in sites:
		if link.startswith(p):
			return __import__(sites[p]).extend_link(link)
	return [link]

def extend_links(links):
	return sum(map(extend_link, links), [])


