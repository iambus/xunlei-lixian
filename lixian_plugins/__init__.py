
def load_plugins():
	import lixian_plugins.commands
	lixian_plugins.commands.load_commands()
	import lixian_query
	lixian_query.load_default_queries()
	lixian_query.load_plugin_queries()
	import lixian_extend_links
	lixian_extend_links.load_parsers()

load_plugins()
