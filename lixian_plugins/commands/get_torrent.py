
from lixian_plugins.api import command

from lixian_cli_parser import command_line_parser, command_line_option
from lixian_cli_parser import with_parser
from lixian_cli import parse_login
from lixian_commands.util import create_client

@command(name='get-torrent', usage='get .torrent by task id or info hash')
@command_line_parser()
@with_parser(parse_login)
@command_line_option('rename', default=True)
def get_torrent(args):
	'''
	usage: lx get-torrent [info-hash|task-id]...
	'''
	client = create_client(args)
	for id in args:
		id = id.lower()
		import re
		if re.match(r'[a-fA-F0-9]{40}$', id):
			torrent = client.get_torrent_file_by_info_hash(id)
		elif re.match(r'\d+$', id):
			import lixian_query
			task = lixian_query.get_task_by_id(client, id)
			id = task['bt_hash']
			id = id.lower()
			torrent = client.get_torrent_file_by_info_hash(id)
		else:
			raise NotImplementedError()
		if args.rename:
			import lixian_hash_bt
			from lixian_encoding import default_encoding
			info = lixian_hash_bt.bdecode(torrent)['info']
			name = info['name'].decode(info.get('encoding', 'utf-8')).encode(default_encoding)
			import re
			name = re.sub(r'[\\/:*?"<>|]', '-', name)
		else:
			name = id
		path = name + '.torrent'
		print path
		with open(path, 'wb') as output:
			output.write(torrent)

