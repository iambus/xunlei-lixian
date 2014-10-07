
def file_path_verification_code_reader(path):
	def reader(image):
		with open(path, 'wb') as output:
			output.write(image)
		print 'Verification code picture is saved to %s, please open it manually and enter what you see.' % path
		code = raw_input('Verification code: ')
		return code
	return reader

def ascii_verification_code_reader(image_data):
	import ascii_verification_code
	print ascii_verification_code.convert_to_ascii(image_data)
	code = raw_input('Verification code: ')
	return code

def default_verification_code_reader(args):
	if args.verification_code_handler == 'ascii':
		return ascii_verification_code_reader
	elif args.verification_code_path:
		return file_path_verification_code_reader(args.verification_code_path)

