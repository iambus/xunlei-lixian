

from lixian import XunleiClient
from lixian_commands.util import *
from lixian_cli_parser import *
from lixian_config import get_config
import lixian_help
from getpass import getpass

def file_path_verification_code_reader(args):
	def reader(image):
		if image:
			with open(args.verification_code_path, 'wb') as output:
				output.write(image)
			if args.verification_code_input_later:
				print 'Verification code picture is saved to %s, please open it manually and run login with --verification-code-input.' % args.verification_code_path
				return exit(1)
			else:
				print 'Verification code picture is saved to %s, please open it manually and enter what you see.' % args.verification_code_path
		code = args.verification_code_input
		if not code:
			code = raw_input('Verification code: ')


		return code
	return reader

def verification_code_reader(args):
	if args.verification_code_path or args.verification_code_input:
		return file_path_verification_code_reader(args)


@command_line_parser(help=lixian_help.login)
@with_parser(parse_login)
@with_parser(parse_logging)
@command_line_value('verification-code-path')
@command_line_option('verification-code-input-later')
@command_line_value('verification-code-input')
def login(args):
	if args.cookies == '-':
		args._args['cookies'] = None
	if len(args) < 1:
		args.username = args.username or XunleiClient(cookie_path=args.cookies, login=False).get_username() or get_config('username') or raw_input('ID: ')
		args.password = args.password or get_config('password') or getpass('Password: ')
	elif len(args) == 1:
		args.username = args.username or XunleiClient(cookie_path=args.cookies, login=False).get_username() or get_config('username')
		args.password = args[0]
		if args.password == '-':
			args.password = getpass('Password: ')
	elif len(args) == 2:
		args.username, args.password = list(args)
		if args.password == '-':
			args.password = getpass('Password: ')
	elif len(args) == 3:
		args.username, args.password, args.cookies = list(args)
		if args.password == '-':
			args.password = getpass('Password: ')
	elif len(args) > 3:
		raise RuntimeError('Too many arguments')
	if not args.username:
		raise RuntimeError("What's your name?")
	if args.cookies:
		print 'Saving login session to', args.cookies
	else:
		print 'Testing login without saving session'
	args.verification_code_reader = verification_code_reader(args)
	XunleiClient(args.username, args.password, args.cookies, login=True, verification_code_reader=args.verification_code_reader, verification_code_fetch=not args.verification_code_input)
