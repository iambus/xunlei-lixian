
def load_plugins():
	import lixian_plugins.commands
	lixian_plugins.commands.load_commands()
	import lixian_query
	lixian_query.load_default_queries()
	lixian_query.load_plugin_queries()
	import lixian_plugins.parsers
	lixian_plugins.parsers.load_parsers()
	# load lixian_plugins/*.py

	import os
	import os.path
	import re
	plugin_dir = os.path.dirname(__file__)
	plugins = os.listdir(plugin_dir)
	plugins = [re.sub(r'\.py$', '', p) for p in plugins if p.endswith('.py') and not p.startswith('_')]
	for p in plugins:
		__import__('lixian_plugins.' + p)

load_plugins()
