# Tests of the common/ helper code.
#
# These only need the code in common/ itself, so they link against
# esdm_common_static_lib rather than the full ESDM library and run without any
# privileges, a server or an initialized DRNG.

common_test_deps = [ dependencies_client, dependency('threads') ]

binhexbin_test = executable(
		'binhexbin_test',
		[ 'binhexbin_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

bitops_test = executable(
		'bitops_test',
		[ 'bitops_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

# conv_be_le.h resolves the byte swaps to compiler builtins unless
# CONVERSION_TEST is defined. Build the same test both ways so the header's own
# rotation-based fallback - what a toolchain without the builtins would use -
# is compiled and executed as well.
conv_be_le_test = executable(
		'conv_be_le_test',
		[ 'conv_be_le_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

conv_be_le_sw_test = executable(
		'conv_be_le_sw_test',
		[ 'conv_be_le_test.c' ],
		c_args: [ '-DCONVERSION_TEST' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

buffer_test = executable(
		'buffer_test',
		[ 'buffer_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

esdm_logger_test = executable(
		'esdm_logger_test',
		[ 'esdm_logger_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

linux_support_test = executable(
		'linux_support_test',
		[ 'linux_support_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

helper_test = executable(
		'helper_test',
		[ 'helper_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

threading_support_test = executable(
		'threading_support_test',
		[ 'threading_support_test.c' ],
		include_directories: include_dirs_server,
		dependencies: common_test_deps,
		link_with: esdm_common_static_lib,
	)

if get_option('testmode').enabled()
	test_pertubation_test = executable(
			'test_pertubation_test',
			[ 'test_pertubation_test.c' ],
			include_directories: include_dirs_server,
			dependencies: common_test_deps,
			link_with: esdm_common_static_lib,
		)

	# The shared memory segment is a system wide singleton keyed by a fixed
	# ftok() value, so this must not run next to anything else that attaches
	# to it - which is every test mode ESDM on the machine.
	test('common test perturbation', test_pertubation_test,
		is_parallel: false)
endif

# Both of these are only compiled into common_src when their option is set.
if get_option('systemd').enabled()
	systemd_support_test = executable(
			'systemd_support_test',
			[ 'systemd_support_test.c' ],
			include_directories: include_dirs_server,
			dependencies: common_test_deps,
			link_with: esdm_common_static_lib,
		)

	test('common systemd support', systemd_support_test)
endif

if get_option('fips140')
	fips_integrity_test = executable(
			'fips_integrity_test',
			[ 'fips_integrity_test.c' ],
			include_directories: include_dirs_server,
			dependencies: common_test_deps,
			link_with: esdm_common_static_lib,
		)

	test('common FIPS integrity check', fips_integrity_test)
endif

test('common hex/bin conversion', binhexbin_test)
test('common bit operations', bitops_test)
test('common endianness conversion', conv_be_le_test)
test('common endianness conversion - software byte swap', conv_be_le_sw_test)
test('common buffer handling', buffer_test)
test('common logger', esdm_logger_test)
test('common helper', helper_test)
test('common Linux support', linux_support_test)

# The threading test occupies an entire thread group at once and waits for
# signals to be delivered, so it neither shares the machine well nor finishes
# within the default timeout on a loaded builder.
test('common threading support', threading_support_test,
	timeout: 120,
	is_parallel: false)
