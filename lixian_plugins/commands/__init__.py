
__all__ = []

commands = {}

extended_commands = []

def update_helps(commands):
	if commands:
		import lixian_help
		lixian_help.extended_usage = '''\nExtended commands:
''' + lixian_help.join_commands([(x[0], x[1]) for x in commands])

	for name, usage, doc in commands:
		setattr(lixian_help, name, doc)

def register_command(command):
	extended_commands.append(command)
	global commands
	commands = dict((x.command_name, x) for x in extended_commands)
	update_helps(sorted((x.command_name, x.command_usage, x.command_help) for x in extended_commands))


def command(name='', usage='', help=''):
	def as_command(f):
		assert usage, 'missing command usage: ' + f.func_name
		f.command_name = name or f.func_name.replace('_', '-')
		f.command_usage = usage
		f.command_help = help or f.func_doc
		import textwrap
		if f.command_help:
			f.command_help = textwrap.dedent(f.command_help)
		register_command(f)
		return f
	return as_command

def load_commands():
	import os
	import os.path
	import re
	command_dir = os.path.dirname(__file__)
	commands = os.listdir(command_dir)
	commands = [re.sub(r'\.py$', '', p) for p in commands if p.endswith('.py') and not p.startswith('_')]
	for p in commands:
		__import__('lixian_plugins.commands.' + p)


