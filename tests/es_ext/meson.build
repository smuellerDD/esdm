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
endif
