
from lixian import XunleiClient
import subprocess
import sys

def urllib2_download(client, download_url, filename):
	'''In the case you don't even have wget...'''
	print 'Downloading', download_url, 'to', filename, '...'
	import urllib2
	request = urllib2.Request(download_url, headers={'Cookie': 'gdriveid='+client.get_gdriveid()})
	response = urllib2.urlopen(request)
	import shutil
	with open(filename, 'wb') as output:
		shutil.copyfileobj(response, output)

def wget_download(client, download_url, filename):
	gdriveid = str(client.get_gdriveid())
	subprocess.call(['wget', '--header=Cookie: gdriveid='+gdriveid, download_url, '-O', filename])

def check_ed2k(url, path):
	raise NotImplementedError()

def usage():
	print '''python lixian_tools.py --username "Your Xunlei account" --password "Your password" --cookies "path to save cookies" link-to-download

Options:
  --username  <arg>    (Optional) Your Xunlei account. You could skip this if you already have live cookies.
  --password  <arg>    (Optional) Your password. You could skip this if you already have live cookies.
  --cookies   <arg>    (Optional) Path to save cookies. If you specify the cookies, next time you don't have to provide the username and password.
  --tool      <arg>    (Optional) Specify the download tool. Only "wget" and "urllib2" are supported in this version.
    [default wget]
  --output    <arg>    (Optional) Path to save the downloaded file
  --task-name <arg>   (Optional) Search cloud task by file name
  --help              Print this help

Examples:
python lixian_tools.py --username "Your Xunlei account" --password "Your password" --cookies "path to save cookies" "ed2k://|file|%5BSC-OL%5D%5BKaiji2%5D%5B25%5D%5BMKV%5D%5BX264_AAC%5D%5B1280X720%5D%5B8E2F2597%5D.gb.ass|48720|12bb92eb635854ee75dba02ddbcdad13|h=kxeezdk2dvzqejb2taj3lthdwvmrfxbt|/"
python lixian_tools.py --cookies "path to save cookies" "ed2k://|file|%5BSC-OL%5D%5BKaiji2%5D%5B25%5D%5BMKV%5D%5BX264_AAC%5D%5B1280X720%5D%5B8E2F2597%5D.gb.ass|48720|12bb92eb635854ee75dba02ddbcdad13|h=kxeezdk2dvzqejb2taj3lthdwvmrfxbt|/"
'''

def parse_command(args=sys.argv[1:]):
	if not args:
		usage()
		sys.exit(1)
	import getopt
	try:
		opts, links = getopt.getopt(args, 'ho:', ['help', 'username=', 'password=', 'cookies=', 'output=', 'tool=', 'link=', 'task-id=', 'task-name='])
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit(2)

	class Args(object):
		def __init__(self, **args):
			self.__dict__.update(args)
		def __getattr__(self, k):
			return self.__dict__.get(k, None)

	args = Args(links=links, tool='wget')
	for o, v in opts:
		if o in ('-h', '--help'):
			usage()
			sys.exit()
		elif o in ('-o', '--output'):
			args.output = v
		elif o.startswith('--'):
			setattr(args, o[2:], v)
			setattr(args, o[2:].replace('-', '_'), v)
		else:
			assert False, 'unhandled option'
	return args

def execute_args(args):
	download = {'wget':wget_download, 'urllib2':urllib2_download}[args.tool]

	if args.links:
		assert len(args.links) == 1
		url = args.links[0]
	else:
		url = args.link
	assert url or args.task_id or args.task_name

	client = XunleiClient(args.username, args.password, args.cookies)
	client.set_page_size(100)
	tasks = client.read_all_completed()
	if url:
		matched = filter(lambda t: t['original_url'] == url, tasks)
		if matched:
			task = matched[0]
		else:
			# if the task doesn't exist yet, add it
			# TODO: check space, check queue, delete after download done, add loggings
			client.add_task(url)
			tasks = client.read_all_completed()
			task = filter(lambda t: t['original_url'] == url, tasks)[0]
	elif args.task_name:
		task = filter(lambda t: t['name'].find(args.task_name) != -1, tasks)[0]
	elif args.task_id:
		task = filter(lambda t: t['id'] == args.task_id, tasks)[0]
	else:
		raise NotImplementedError()

	download_url = str(task['xunlei_url'])
	filename = args.output or task['name'].encode(sys.getfilesystemencoding())
	referer = str(client.get_referer())
	gdriveid = str(client.get_gdriveid())

	download(client, download_url, filename)

def execute_command(args=sys.argv[1:]):
	execute_args(parse_command(args))

def main():
	execute_args(parse_command())

if __name__ == '__main__':
	main()

#execute_command(['--cookies', 'xunlei.cookies', '--output', 'quick.txt', '--task-name', 'quick', '--tool', 'urllib2'])

