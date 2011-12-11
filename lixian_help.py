
basic_usage = '''python lixian_cli.py <command> [<args>]

Basic commands
 help       try this help...
 login      login Xunlei cloud
 download   download tasks from Xunlei cloud
 list       list tasks on Xunlei cloud
 add        add tasks to Xunlei cloud
 delete     delete tasks from Xunlei cloud
 pause      pause tasks on Xunlei cloud
 restart    restart tasks on Xunlei cloud
 config     save configuration so you don't have to repeat it
 info       print user id, internal user id, and gdriveid
 logout     logout from Xunlei cloud
'''

def usage():
	return basic_usage + '''
Use 'python lixian_cli.py help' for details.
Use 'python lixian_cli.py help <command>' for more information on a specific command.
Check https://github.com/iambus/xunlei-lixian for detailed (and Chinese) doc.'''

help_help = '''Get helps:
  python lixian_cli.py help help
  python lixian_cli.py help examples
  python lixian_cli.py help readme
  python lixian_cli.py help <command>'''

help = help_help

welcome = '''Python script for Xunlei cloud.

Basic usage:
''' + basic_usage + '\n' + help_help

def examples():
	return '''python lixian_cli.py login "Your Xunlei account" "Your password"
python lixian_cli.py login "Your password"
python lixian_cli.py login

python lixian_cli.py config username "Your Xunlei account"
python lixian_cli.py config password "Your password"

python lixian_cli.py list
python lixian_cli.py list --completed
python lixian_cli.py list --completed --name --original-url --download-url --no-status --no-id
python lixian_cli.py list id1 id2
python lixian_cli.py list zip rar
python lixian_cli.py list --search zip rar

python lixian_cli.py download task-id
python lixian_cli.py download ed2k-url
python lixian_cli.py download --tool wget ed2k-url
python lixian_cli.py download --tool asyn ed2k-url
python lixian_cli.py download ed2k-url --output "file to save"
python lixian_cli.py download id1 id2 id3
python lixian_cli.py download url1 url2 url3
python lixian_cli.py download --input download-urls-file
python lixian_cli.py download --input download-urls-file --delete
python lixian_cli.py download --input download-urls-file --ouput-dir root-dir-to-save-files
python lixian_cli.py download bt://torrent-info-hash
python lixian_cli.py download --torrent 1.torrent
python lixian_cli.py download --torrent torrent-info-hash
python lixian_cli.py download --torrent http://xxx/xxx.torrent

python lixian_cli.py add url
python lixian_cli.py add --torrent 1.torrent
python lixian_cli.py add --torrent torrent-info-hash
python lixian_cli.py add --torrent http://xxx/xxx.torrent

python lixian_cli.py delete task-id
python lixian_cli.py delete url
python lixian_cli.py delete file-name-on-cloud-to-delete

python lixian_cli.py pause id

python lixian_cli.py restart id

python lixian_cli.py logout

Please check https://github.com/iambus/xunlei-lixian for detailed (and Chinese) doc.
'''

def readme():
	import sys
	import os.path
	doc = os.path.join(sys.path[0], 'README')
	with open(doc) as txt:
		return txt.read().decode('utf-8')


login    = '''python lixian_cli.py login <username> <password>

login Xunlei cloud'''

download = '''python lixian_cli.py download url...

download tasks from Xunlei cloud'''

list     = '''python lixian_cli.py list

list tasks on Xunlei cloud'''

add      = '''python lixian_cli.py add url...

add tasks to Xunlei cloud'''

delete   = '''python lixian_cli.py delete id...

delete tasks from Xunlei cloud'''

pause    = '''python lixian_cli.py pause id...

pause tasks on Xunlei cloud'''

restart  = '''python lixian_cli.py restart id...

restart tasks on Xunlei cloud'''

config   = '''python lixian_cli.py config key [value]

save configuration so you don't have to repeat it'''

info     = '''python lixian_cli.py info

print user id, internal user id, and gdriveid'''

logout   = '''python lixian_cli.py logout

logout from Xunlei cloud'''


