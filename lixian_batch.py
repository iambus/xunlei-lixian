#!/usr/bin/env python

import sys
import os.path
import subprocess

def download_batch(files):
	for f in files:
		print 'Downloading', f, '...'
		f = os.path.abspath(f)
		os.chdir(os.path.dirname(f))
		subprocess.call(['lx', 'download', '--input', f, '--delete', '--continue'])

if __name__ == '__main__':
	download_batch(sys.argv[1:])

