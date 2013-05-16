
from lixian_plugins.api import command


from lixian_cli_parser import command_line_parser
from lixian_cli_parser import with_parser
from lixian_cli_parser import command_line_option, command_line_value
from lixian_commands.util import parse_login, create_client

@command(usage='export task download urls')
@command_line_parser()
@with_parser(parse_login)
@command_line_option('all')
@command_line_value('category')
def export_download_urls(args):
	'''
	usage: lx export-download-urls [id|name]...
	'''
	assert len(args) or args.all or args.category, 'Not enough arguments'
	client = create_client(args)
	import lixian_query
	tasks = lixian_query.search_tasks(client, args)
	urls = []
	for task in tasks:
		if task['type'] == 'bt':
			subs, skipped, single_file = lixian_query.expand_bt_sub_tasks(task)
			if not subs:
				continue
			if single_file:
				urls.append((subs[0]['xunlei_url'], subs[0]['name'], None))
			else:
				for f in subs:
					urls.append((f['xunlei_url'], f['name'], task['name']))
		else:
			urls.append((task['xunlei_url'], task['name'], None))
	for url, _, _ in urls:
		print url
