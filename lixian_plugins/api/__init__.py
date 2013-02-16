
__all__ = ['page_parser', 'command']

def page_parser(pattern):
	def f(extend_links):
		import lixian_extend_links
		patterns = pattern if type(pattern) is list else [pattern]
		for p in patterns:
			lixian_extend_links.register_parser(p, extend_links)
	return f

from lixian_commands import command

