
def get_aliases():
	return {'d': 'download', 'l': 'list', 'a': 'add', 'x': 'delete'}

def get_alias(a):
	aliases = get_aliases()
	if a in aliases:
		return aliases[a]

def to_alias(a):
	return get_alias(a) or a

