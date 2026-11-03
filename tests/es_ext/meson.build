if get_option('esdm-es-ext').enabled()
	include_dirs_es_ext_test = [ include_dirs_es_ext,
				     include_directories('../common') ]

	es_ext_proto_test = executable('es_ext_proto_test',
		[ 'es_ext_proto_test.c', es_ext_proto_src ],
		include_directories: include_dirs_es_ext_test,
		dependencies: protobuf_c_dep,
	)
	test('External ES protocol', es_ext_proto_test, suite: 'es_ext')

	# The provider program of the test source, see es_ext_test_plugin.c
	es_ext_test_provider = executable('es_ext_test_provider',
		'es_ext_test_plugin.c',
		c_args: [ '-DES_EXT_TEST_PROVIDER' ],
		include_directories: include_dirs_es_ext_test,
		link_with: [ esdm_es_ext_lib.get_static_lib(),
			     esdm_common_static_lib ],
		dependencies: [ dependency('threads'), json_c_dep,
				protobuf_c_dep ])

	# The example, built as a provider of its own would be - against the
	# installed header (include/esdm) and the shared library - reading a
	# device, and an empty FIFO: a device that stalls
	subdir('include/esdm')
	es_ext_example_fifo = meson.current_build_dir() / 'es_ext_example.fifo'
	es_ext_examples = []
	foreach ex : [ [ 'es_ext_example', '/dev/urandom' ],
		       [ 'es_ext_example_fifo', es_ext_example_fifo ] ]
		es_ext_examples += executable(ex[0],
			'../../es-ext/example/esdm_es_ext_example.c',
			c_args: [ '-DESDM_ES_EXT_EXAMPLE_DEVICE="' + ex[1] + '"' ],
			include_directories: include_directories('include'),
			implicit_include_directories: false,
			link_with: esdm_es_ext_lib.get_shared_lib())
	endforeach

	es_ext_lib_test = executable('es_ext_lib_test',
		[ 'es_ext_lib_test.c', 'es_ext_test_plugin.c' ],
		include_directories: include_dirs_es_ext_test,
		link_with: esdm_es_ext_lib.get_static_lib(),
		dependencies: [ dependency('threads'), json_c_dep, protobuf_c_dep ],
	)
	test('External ES library', es_ext_lib_test, suite: 'es_ext')

	es_ext_provider_test = executable('es_ext_provider_test',
		[ 'es_ext_provider_test.c', es_ext_proto_src ],
		include_directories: include_dirs_es_ext_test,
		dependencies: [ json_c_dep, protobuf_c_dep ],
	)
	test('External ES provider program', es_ext_provider_test,
		args: [ es_ext_test_provider, es_ext_examples,
			es_ext_example_fifo ],
		depends: [ es_ext_test_provider ] + es_ext_examples,
		suite: 'es_ext', timeout: 60)

	# Against SoftHSM behind the shim module, skipped without softhsm2-util
	if get_option('es_pkcs11').enabled()
		es_pkcs11_shim = shared_module('esdm_es_pkcs11_shim',
			'es_pkcs11_shim.c',
			dependencies: [ dependency('dl') ],
		)
		es_pkcs11_test = executable('es_pkcs11_test',
			[ 'es_pkcs11_test.c', es_ext_proto_src ],
			include_directories: include_dirs_es_ext_test,
			dependencies: [ dependencies_client,
					dependency('threads'), json_c_dep ],
			link_with: esdm_common_static_lib,
		)
		test('esdm-es-pkcs11', es_pkcs11_test,
			args: [ esdm_es_pkcs11, es_pkcs11_shim ],
			depends: [ esdm_es_pkcs11, es_pkcs11_shim ],
			suite: 'es_ext', timeout: 120)
	endif

	# Against a fake pcscd: only the headers of pcsc-lite are needed
	if get_option('es_pcsc').enabled()
		es_pcsc_test = executable('es_pcsc_test',
			[ '../../es-ext/pcsc/esdm_es_pcsc.c', 'es_pcsc_test.c' ],
			include_directories: [ include_dirs_es_ext_test,
					       include_directories('../../es-ext/pcsc') ],
			dependencies: [ json_c_dep, protobuf_c_dep,
					dependency('libpcsclite').partial_dependency(
						compile_args: true) ],
			link_with: esdm_common_static_lib,
		)
		test('esdm-es-pcsc', es_pcsc_test, args: esdm_es_pcsc,
			depends: esdm_es_pcsc, suite: 'es_ext')
	endif
endif

# The ESDM side, its source compiled into the tests
if get_option('es_ext').enabled() and get_option('esdm-es-ext').enabled()
	foreach t : [ [ 'es_extsock_test', 'External ES source of the ESDM' ],
		      [ 'es_ext_init_test',
			'External ES self test before the initial seeding' ] ]
		test(t[1],
			executable(t[0],
				[ esdm_ipc_ns, t[0] + '.c', 'es_ext_test_plugin.c' ],
				dependencies: dependencies_server,
				include_directories: [ include_dirs_server,
						       include_directories('../common') ],
				link_with: [ esdm_static_lib,
					     esdm_es_ext_lib.get_static_lib() ]),
			suite: 'es_ext', timeout: 60)
	endforeach

	# Skipped (77) unless run as root
	if get_option('esdm-server').enabled()
		es_ext_server_test = executable('es_ext_server_test',
			'es_ext_server_test.c',
			include_directories: [ include_dirs_client,
					       include_directories('../common') ],
			dependencies: dependencies_client + [ json_c_dep ],
			link_with: [ esdm_common_static_lib,
				     esdm_rpc_client_lib ],
		)
		test('esdm-server with an external entropy source',
			es_ext_server_test,
			args: [ esdm_server, es_ext_test_provider ],
			depends: [ esdm_server, es_ext_test_provider ],
			suite: 'es_ext', timeout: 120)
	endif

	if get_option('es_pkcs11').enabled()
		es_pkcs11_esdm_test = executable('es_pkcs11_esdm_test',
			[ esdm_ipc_ns, 'es_pkcs11_esdm_test.c' ],
			dependencies: dependencies_server,
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
			link_with: esdm_static_lib,
		)
		test('esdm-es-pkcs11 read by the ESDM', es_pkcs11_esdm_test,
			args: [ esdm_es_pkcs11, es_pkcs11_shim ],
			depends: [ esdm_es_pkcs11, es_pkcs11_shim ],
			suite: 'es_ext', timeout: 60)
	endif
endif
