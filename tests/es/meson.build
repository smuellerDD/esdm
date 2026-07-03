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

# The following hardware/service-backed sources may be absent on the test
# machine; their tests are structural / graceful-absence checks (see the file
# headers) and pass whether or not the device is present.
if get_option('es_hwrand').enabled()
	es_hwrand_tester = executable(
		'es_hwrand_tester',
		[ 'es_hwrand_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Linux HW Random', es_hwrand_tester)
endif

if get_option('es_tpm2').enabled()
	es_tpm2_tester = executable(
		'es_tpm2_tester',
		[ 'es_tpm2_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES TPM 2.0', es_tpm2_tester)
endif

if get_option('es_pkcs11').enabled()
	es_pkcs11_tester = executable(
		'es_pkcs11_tester',
		[ 'es_pkcs11_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES PKCS11', es_pkcs11_tester)
endif

if get_option('es_jent_kernel').enabled()
	es_jent_kernel_tester = executable(
		'es_jent_kernel_tester',
		[ 'es_jent_kernel_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Kernel Jitter RNG', es_jent_kernel_tester)
endif
