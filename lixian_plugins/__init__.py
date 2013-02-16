
def load_plugins():
	import lixian_commands
	lixian_commands.load_commands()
	import lixian_extend_links
	lixian_extend_links.load_parsers()

load_plugins()
