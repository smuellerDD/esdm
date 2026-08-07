# Every test here drives the ESDM in process and therefore touches the
# machine-global System V names - see tests/test_ipc_ns.c.
esdm_ipc_ns = files('../test_ipc_ns.c')

es_mgr_monitor_tester = executable(
	'es_mgr_monitor_tester',
	[ esdm_ipc_ns, 'es_mgr_monitor_test.c' ],
	dependencies: dependencies_server,
	include_directories: include_dirs_server,
	link_with: esdm_static_lib,
)

test('ES manager monitor', es_mgr_monitor_tester, timeout: 120)

if get_option('es_jent').enabled()
	es_jent_tester = executable(
		'es_jent_tester',
		[ esdm_ipc_ns, 'es_jent_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Jitter RNG', es_jent_tester, timeout: 300)
endif

if get_option('es_cpu').enabled()
	es_cpu_tester = executable(
		'es_cpu_tester',
		[ esdm_ipc_ns, 'es_cpu_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES CPU', es_cpu_tester)
endif

if get_option('es_kernel').enabled()
	es_krng_tester = executable(
		'es_krng_tester',
		[ esdm_ipc_ns, 'es_krng_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Kernel', es_krng_tester)
endif

if get_option('es_sched').enabled()
	es_sched_tester = executable(
		'es_sched_tester',
		[ esdm_ipc_ns, 'es_sched_test.c' ],
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
		[ esdm_ipc_ns, 'es_hwrand_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Linux HW Random', es_hwrand_tester)
endif

if get_option('es_tpm2').enabled()
	es_tpm2_tester = executable(
		'es_tpm2_tester',
		[ esdm_ipc_ns, 'es_tpm2_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES TPM 2.0', es_tpm2_tester)
endif


if get_option('es_sched_ebpf').enabled()
	es_sched_ebpf_tester = executable(
		'es_sched_ebpf_tester',
		[ esdm_ipc_ns, 'es_sched_ebpf_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Scheduler eBPF', es_sched_ebpf_tester, timeout: 120)
endif

if get_option('es_irq_ebpf').enabled()
	es_irq_ebpf_tester = executable(
		'es_irq_ebpf_tester',
		[ esdm_ipc_ns, 'es_irq_ebpf_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Interrupt eBPF', es_irq_ebpf_tester, timeout: 120)
endif

if get_option('es_pkcs11').enabled()
	es_pkcs11_tester = executable(
		'es_pkcs11_tester',
		[ esdm_ipc_ns, 'es_pkcs11_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)
	test('ES PKCS11', es_pkcs11_tester)
endif

if get_option('es_sched_ebpf').enabled() or get_option('es_irq_ebpf').enabled()
	es_ebpf_health_tester = executable(
		'es_ebpf_health_tester',
		[ esdm_ipc_ns, 'es_ebpf_health_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES eBPF health cutoffs', es_ebpf_health_tester)
endif

if get_option('es_jent_kernel').enabled()
	es_jent_kernel_tester = executable(
		'es_jent_kernel_tester',
		[ esdm_ipc_ns, 'es_jent_kernel_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	test('ES Kernel Jitter RNG', es_jent_kernel_tester)
endif
