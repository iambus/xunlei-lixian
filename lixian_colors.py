
import os
import sys

def get_console_type():
	import sys
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

class ScopedColors(Console):
	def __init__(self, *args):
		Console.__init__(self, *args)
	def __call__(self):
		console = self
		import sys
		class Scoped:
			def __enter__(self):
				self.stdout = sys.stdout
				sys.stdout = console
			def __exit__(self, type, value, traceback):
				sys.stdout = self.stdout
		return Scoped()

colors = ScopedColors()

