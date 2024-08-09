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
	version: '1.1.2',
	default_options: [
		'warning_level=3',
		'optimization=2',
		'strip=true',
		'b_lto=true',
		'b_staticpic=true',
		'b_pie=true',
		'b_asneeded=true',
		# set the C++ std for the botan frontend here, C++ only gets used if botan-rng is enabled
		'cpp_std=c++20',
	])

################################################################################
# Generic project defines
################################################################################

cc = meson.get_compiler('c')

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
		       '-Wswitch-enum',
		       '-Wformat=2',
                       ],
		       language : 'c')

# More hardening
if cc.has_argument('-fzero-call-used-regs=used-gpr')
	add_global_arguments([ '-fzero-call-used-regs=used-gpr' ],
			     language: 'c')
endif

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

# Prepare distribution
dist_script = find_program('addon/sanity_checks.sh', required: true)
meson.add_dist_script(dist_script, meson.project_version())

################################################################################
# Project-specific defines
################################################################################

dependencies = [ dependency('libprotobuf-c'), dependency('threads') ]

pkgconfig = import('pkgconfig')

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

if get_option('esdm-server').disabled() and get_option('botan-rng').enabled()
	error('Botan RNG support requires the ESDM server')
endif

if get_option('esdm-server').disabled() and get_option('openssl-rand-provider').enabled()
	error('OpenSSL RAND provider support requires the ESDM server')
endif

if get_option('crypto_backend') == 'builtin'
	if get_option('drng_hash_drbg').enabled() and \
	   get_option('drng_chacha20').enabled()
		error('Only one DRNG can be enabled')
	endif

	if get_option('hash_sha512').enabled() and \
	   get_option('hash_sha3_512').enabled()
		error('Only one conditioning hash can be enabled')
	endif
endif

if get_option('es_jent_kernel').enabled()
	dependencies_server += [ dependency('libkcapi', required: true) ]
endif

if get_option('esdm-server').enabled()
	subdirs += [ 'frontends/server', 'frontends/server-signal-helper' ]
endif

if get_option('linux-devfiles').enabled()
	subdirs += [ 'frontends/cuse' ]
endif

if get_option('linux-getrandom').enabled()
	subdirs += [ 'frontends/getrandom' ]
endif

if get_option('botan-rng').enabled()
	add_languages('cpp', required: true)
	botan_dep = dependency('botan-3', required: true)
	subdirs += [ 'frontends/botan-rng' ]
	include_dirs_botan_rng = [ include_directories('frontends/botan-rng') ]
endif

if get_option('openssl-rand-provider').enabled()
	openssl_dep = dependency('openssl', required: true, version : '>=3.0')
	subdirs += [ 'frontends/openssl-provider' ]
endif

if get_option('esdm-aux-client').enabled()
	subdirs += [ 'frontends/aux-client' ]
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
if get_option('botan-rng').enabled()
	testdirs += [
		'tests/botan-rng',
	]
endif
if get_option('openssl-rand-provider').enabled()
testdirs += [
	'tests/openssl-rand-provider',
]
endif
foreach n : testdirs
	subdir(n)
endforeach

