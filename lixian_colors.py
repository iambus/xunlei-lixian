
import os
import sys

def get_console_type():
	if sys.stdout.isatty() and sys.stderr.isatty():
		import platform
		if platform.system() == 'Windows':
			import lixian_colors_win32
			return lixian_colors_win32.WinConsole
		else:
			import lixian_colors_linux
			return lixian_colors_linux.AnsiConsole
	else:
		import lixian_colors_console
		return lixian_colors_console.Console

Console = get_console_type()

def get_softspace(output):
	if hasattr(output, 'softspace'):
		return output.softspace
	import lixian_colors_console
	if isinstance(output, lixian_colors_console.Console):
		return get_softspace(output.output)
	return 0

class ScopedColors(Console):
	def __init__(self, *args):
		Console.__init__(self, *args)
	def __call__(self):
		console = self
		class Scoped:
			def __enter__(self):
				self.stdout = sys.stdout
				softspace = get_softspace(sys.stdout)
				sys.stdout = console
				sys.stdout.softspace = softspace
			def __exit__(self, type, value, traceback):
				softspace = get_softspace(sys.stdout)
				sys.stdout = self.stdout
				sys.stdout.softspace = softspace
		return Scoped()

class RootColors:
	def __getattr__(self, name):
		return getattr(ScopedColors(), name)

colors = RootColors()

