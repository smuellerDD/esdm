if get_option('es_jent').enabled()
	es_jent_tester = executable(
		'es_jent_tester',
		[ 'es_jent_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Jitter RNG', es_jent_tester, timeout: 300)
endif

if get_option('es_cpu').enabled()
	es_cpu_tester = executable(
		'es_cpu_tester',
		[ 'es_cpu_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES CPU', es_cpu_tester)
endif

if get_option('es_kernel').enabled()
	es_krng_tester = executable(
		'es_krng_tester',
		[ 'es_krng_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Kernel', es_krng_tester)
endif

if get_option('es_sched').enabled()
	es_sched_tester = executable(
		'es_sched_tester',
		[ 'es_sched_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Scheduler', es_sched_tester, timeout: 70)
endif
