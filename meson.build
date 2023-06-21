################################################################################
# Version Change Definition
################################################################################
# Major Version: API / ABI incompatible changes, functional changes that require
#		 consumer to be updated (as long as this number is zero, the API
#		 is not considered stable and can change without a bump of the
#		 major version).
# Minor Version: API compatible, ABI may change, functional enhancements only,
#		 consumer can be left unchanged if enhancements are not
#		 considered. Yet, consumer must be recompiled.
# Patchlevel Version: API / ABI compatible, no functional changes, no
#		      enhancements, bug fixes only.
project('esdm', 'c',
	version: '0.6.0',
	default_options: [
		'warning_level=3',
		'optimization=2',
		'strip=true',
		'b_lto=true',
		'b_staticpic=true',
		'b_pie=true',
	])

################################################################################
# Generic project defines
################################################################################

# Hardening Compiler flags
add_global_arguments([ '-fstack-protector-strong',
		       '-fwrapv',
		       '--param', 'ssp-buffer-size=4',
		       '-fvisibility=hidden',
		       '-Wconversion',
		       '-Wcast-align',
		       '-Wmissing-field-initializers',
		       '-Wshadow',
                       '-Wmissing-prototypes',
		       '-Wswitch-enum' ],
		       language : 'c')

if get_option('optimization') != '0'
	add_global_arguments([ '-D_FORTIFY_SOURCE=2' ], language: 'c')
else
	add_global_arguments([ '-DDEBUG' ], language: 'c')
endif

# Versioning information
version_array = meson.project_version().split('.')
add_global_arguments(['-DMAJVERSION=' + version_array[0],
		      '-DMINVERSION=' + version_array[1],
		      '-DPATCHLEVEL=' + version_array[2],
		      '-DVERSION="' + meson.project_version() + '"'],
		      language : 'c')

# Dead-code-stripping support
add_global_arguments(['-ffunction-sections', '-fdata-sections'], language : 'c')
add_project_link_arguments('-Wl,--gc-sections', language : 'c')

# Link for full RELRO
add_project_link_arguments('-Wl,-z,relro', language : 'c')
add_project_link_arguments('-Wl,-z,now', language : 'c')

# No executable stack
add_project_link_arguments('-Wl,-z,noexecstack', language : 'c')

# Only link to truly needed libraries
add_project_link_arguments('-Wl,--as-needed', language : 'c')

# Prepare distribution
dist_script = find_program('addon/sanity_checks.sh', required: true)
meson.add_dist_script(dist_script, meson.project_version())

################################################################################
# Project-specific defines
################################################################################

cc = meson.get_compiler('c')
dependencies = [ dependency('libprotobuf-c'), dependency('threads') ]

include_user_files = [ ]

include_dirs_server = include_directories([ 'esdm',
					    'crypto',
					    'common',
					    'service-rpc/service',
					    'service-rpc/server' ])
dependencies_server = dependencies

include_dirs_client = include_directories([ 'common',
					    'service-rpc/service',
					    'service-rpc/client' ])
dependencies_client = dependencies

subdirs = [ 'common', 'crypto', 'esdm',
	    'service-rpc/server', 'service-rpc/service', 'service-rpc/client/' ]

if get_option('esdm-server').disabled() and get_option('linux-devfiles').enabled()
	error('Linux device file support requires the ESDM server')
endif

if get_option('esdm-server').disabled() and get_option('linux-getrandom').enabled()
	error('Linux getrandom support requires the ESDM server')
endif

if get_option('drng_hash_drbg').enabled() and get_option('drng_chacha20').enabled()
	error('Only one DRNG can be enabled')
endif

if get_option('hash_sha512').enabled() and get_option('hash_sha3_512').enabled()
	error('Only one conditioning hash can be enabled')
endif

if get_option('gnutls').enabled()
	error('GnuTLS support currently not available as GnuTLS cannot handle hash context on stack')
endif

if get_option('gnutls').enabled() and (get_option('drng_hash_drbg').enabled() or get_option('drng_chacha20').enabled() or get_option('hash_sha512').enabled() or get_option('hash_sha3_512').enabled())
	error('GnuTLS support requires disabling of built-in crypto support')
endif

if get_option('esdm-server').enabled()
	subdirs += [ 'frontends/server' ]
endif

if get_option('linux-devfiles').enabled()
	subdirs += [ 'frontends/cuse' ]
endif

if get_option('linux-getrandom').enabled()
	subdirs += [ 'frontends/getrandom' ]
endif

foreach n : subdirs
	subdir(n)
endforeach

install_headers(include_user_files, subdir: 'esdm')

################################################################################
# Execute testing
################################################################################

testdirs = [
	'tests/crypto',
	'tests/cuse',
	'tests/es',
	'tests/esdm',
	'tests/getrandom',
	#'tests/misc',
	'tests/rpc_client',
	]
foreach n : testdirs
	subdir(n)
endforeach

