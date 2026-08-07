# Tests of the esdm-server command line.
#
# The daemon is executed rather than linked, because what is under test is what
# a user gets from it: the usage, the version, and what it makes of the options
# before it decides whether it may run at all.
if get_option('esdm-server').enabled()
	server_cli_test = executable(
			'server_cli_test',
			[ 'server_cli_test.c' ],
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
		)

	test('esdm-server command line', server_cli_test,
		args: [ esdm_server.full_path() ])
endif
