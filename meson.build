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
	version: '0.2.0',
	default_options: [
		'warning_level=3',
		'optimization=2',
		'strip=true',
		'b_lto=true',
		'b_staticpic=true',
		'b_pie=true',
		'c_std=gnu18',
	])

################################################################################
# Generic project defines
################################################################################

# Hardening Compiler flags
add_global_arguments([ '-D_FORTIFY_SOURCE=2',
		       '-fstack-protector-strong',
		       '-fwrapv',
		       '--param', 'ssp-buffer-size=4',
		       '-fvisibility=hidden',
		       '-Wconversion',
		       '-Wcast-align',
		       '-Wmissing-field-initializers',
		       '-Wshadow',
		       '-Wswitch-enum' ],
		       language : 'c')

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

# Only link to truly needed libraries
add_project_link_arguments('-Wl,--as-needed', language : 'c')

# Prepare distribution
dist_script = find_program('addon/sanity_checks.sh', required: true)
meson.add_dist_script(dist_script, meson.project_version())

################################################################################
# Project-specific defines
################################################################################

cc = meson.get_compiler('c')
dependencies = [ dependency('libprotobuf-c') ]
dependencies += cc.find_library('protobuf-c-rpc' )

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

