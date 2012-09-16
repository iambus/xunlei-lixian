
import os
import sys

def Console():
	import sys
	if sys.stdout.isatty() and sys.stderr.isatty():
		import platform
		if platform.system() == 'Windows':
			import lixian_colors_win32
			return lixian_colors_win32.WinConsole()
		else:
			import lixian_colors_linux
			return lixian_colors_linux.AnsiConsole()
	else:
		import lixian_colors_console
		return lixian_colors_console.Console()

