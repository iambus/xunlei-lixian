

def extend_link(link):
	if link.startswith('http://kuai.xunlei.com/d/'):
		import lixian_kuai
		return [x['url'] for x  in lixian_kuai.kuai_links(link)]
	else:
		return [link]

def extend_links(links):
	return sum(map(extend_link, links), [])


