
__all__ = ['command',
           'user_query', 'extract_info_hash_from_url', 'download_torrent_from_url',
           'page_parser']

##################################################
# commands
##################################################

from lixian_plugins.commands import command

##################################################
# queries
##################################################

from lixian_query import user_query

def extract_info_hash_from_url(regexp):
	import lixian_queries
	import re
	@user_query
	def processor(base, x):
		m = re.match(regexp, x)
		if m:
			return lixian_queries.BtHashQuery(base, m.group(1))

def download_torrent_from_url(regexp):
	import lixian_queries
	import re
	@user_query
	def processor(base, x):
		if re.match(regexp, x):
			return lixian_queries.bt_url_processor(base, x)

##################################################
# parsers
##################################################

def page_parser(pattern):
	def f(extend_links):
		import lixian_extend_links
		patterns = pattern if type(pattern) is list else [pattern]
		for p in patterns:
			lixian_extend_links.register_parser(p, extend_links)
	return f
