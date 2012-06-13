
##################################################

def print_hash(args):
	#assert len(args) == 1
	import lixian_hash
	#import lixian_hash_ed2k
	#print 'ed2k:', lixian_hash_ed2k.hash_file(args[0])
	#print 'dcid:', lixian_hash.dcid_hash_file(args[0])
	from lixian_cli_parser import expand_command_line
	lixian_hash.main(expand_command_line(args))

hash_help = '''
lx hash --sha1 file...
lx hash --md5 file...
lx hash --md4 file...
lx hash --ed2k file...
lx hash --info-hash xxx.torrent...
lx hash --verify-sha1 file hash
lx hash --verify-md5 file hash
lx hash --verify-md4 file hash
lx hash --verify-ed2k file ed2k://...
lx hash --verify-info-hash file xxx.torrent
'''

##################################################

def lx_diagnostics(args):
	import lixian_diagnostics
	lixian_diagnostics.diagnostics()

diagnostics_help = 'usage: lx diagnostics'

##################################################

def decode_url(args):
	from lixian_url import url_unmask
	for x in args:
		print url_unmask(x)

decode_url_help = 'usage: lx decode-url thunder://...'

##################################################

def kuai(args):
	import lixian_kuai
	lixian_kuai.main(args)

kuai_help = '''usage: lx kuai http://kuai.xunlei.com/d/xxx...

Note that you can simply use:
 lx add http://kuai.xunlei.com/d/xxx...
or:
 lx download http://kuai.xunlei.com/d/xxx...
'''

##################################################
# update helps
##################################################

extended_commands = [
		['hash', print_hash, 'compute hashes', hash_help.strip()],
		['diagnostics', lx_diagnostics, 'print helpful information for diagnostics', diagnostics_help],
		['decode-url', decode_url, 'convert thunder:// (and more) to normal url', decode_url_help],
		['kuai', kuai, 'parse links from kuai.xunlei.com', kuai_help],
		]

commands = dict(x[:2] for x in extended_commands)

def update_helps(commands):
	helps = dict((name, doc) for (name, usage, doc) in commands)

	if commands:
		import lixian_help
		lixian_help.extended_usage = '''\nExtended commands:
''' + lixian_help.join_commands([(x[0], x[1]) for x in commands])

	for name, usage, doc in commands:
		assert not hasattr(lixian_help, name)
		setattr(lixian_help, name, doc)

update_helps([(x[0], x[2], x[3]) for x in extended_commands])

