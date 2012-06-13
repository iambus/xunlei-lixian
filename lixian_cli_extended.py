
##################################################

def print_hash(args):
	assert len(args) == 1
	import lixian_hash
	import lixian_hash_ed2k
	print 'ed2k:', lixian_hash_ed2k.hash_file(args[0])
	print 'dcid:', lixian_hash.dcid_hash_file(args[0])

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
# update helps
##################################################

extended_commands = [
		['hash', print_hash, 'compute hashes', 'usage: lx hash file'],
		['diagnostics', lx_diagnostics, 'print helpful information for diagnostics', diagnostics_help],
		['decode-url', decode_url, 'convert thunder:// (and more) to normal url', decode_url_help],
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

