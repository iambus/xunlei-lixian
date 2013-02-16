__author__ = 'Boyu Guo <iambus@gmail.com>'

def page_parser(pattern):
	def f(extend_links):
		import lixian_extend_links
		patterns = pattern if type(pattern) is list else [pattern]
		for p in patterns:
			lixian_extend_links.register_parser(p, extend_links)
	return f
