
def file_path_verification_code_reader(path):
	def reader(image):
		with open(path, 'wb') as output:
			output.write(image)
		print 'Verification code picture is saved to %s, please open it manually and enter what you see.' % path
		code = raw_input('Verification code: ')
		return code
	return reader

def default_verification_code_reader(args):
	if args.verification_code_path:
		return file_path_verification_code_reader(args.verification_code_path)
