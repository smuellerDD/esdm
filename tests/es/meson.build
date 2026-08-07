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

# Whatever entropy sources this build and this machine actually have - the test
# walks the ES manager's table rather than naming any of them, so it needs no
# option guard of its own.
es_seed_cycle_tester = executable(
	'es_seed_cycle_tester',
	[ esdm_ipc_ns, 'es_seed_cycle_test.c' ],
	dependencies: dependencies_server,
	include_directories: include_dirs_server,
	link_with: esdm_static_lib,
)

# Serial: it reports durations, and a duration measured while the rest of the
# suite has the machine is a measure of the suite.
test('ES seed cycle duration', es_seed_cycle_tester,
	timeout: 300,
	is_parallel: false,
	priority: -10)

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

	# RDRAND is unreachable through the entropy source on every CPU that has
	# RDSEED, so the two instructions are driven directly - see the file
	# header. Needs no ESDM around it, only the logger the header calls.
	if host_machine.cpu_family() in [ 'x86', 'x86_64' ]
		es_cpu_x86_tester = executable(
			'es_cpu_x86_tester',
			'es_cpu_x86_test.c',
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
			dependencies: dependencies_server,
			link_with: esdm_common_static_lib,
		)

		test('ES CPU x86 RDSEED/RDRAND', es_cpu_x86_tester)
	endif

	# The compressing data path is selected by a multiplier that is fixed at
	# build time and is 1 in every configuration this suite is built in, so
	# the entropy source is compiled into the test with the build option
	# raised - see the file header.
	es_cpu_compress_tester = executable(
		'es_cpu_compress_tester',
		[ esdm_ipc_ns, 'es_cpu_compress_test.c' ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		dependencies: dependencies_server,
		link_with: esdm_static_lib,
	)

	test('ES CPU compressing path', es_cpu_compress_tester)
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

if get_option('es_irq').enabled()
	es_irq_tester = executable(
		'es_irq_tester',
		[ esdm_ipc_ns, 'es_irq_test.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

	# The interrupt generator sleeps 5000 times per round, so the wall clock
	# is dominated by the rounds rather than by the work.
	test('ES Interrupt', es_irq_tester, timeout: 300)
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

	# With a TPM behind it the test drives the device itself, including a
	# full fill of the block cache - one command exchange per block, and a
	# software TPM in an emulated machine is not quick about them.
	test('ES TPM 2.0', es_tpm2_tester, timeout: 120)
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

	# The test above passes with the source switched off for want of a
	# token, so it never reaches the half that matters. SoftHSM is a
	# PKCS#11 module that needs no hardware, so when the build points at
	# one this test creates a token and drives the source against it for
	# real. It skips at runtime if softhsm2-util is not installed.
	if get_option('es_pkcs11_module_path') != ''
		es_pkcs11_softhsm_tester = executable(
			'es_pkcs11_softhsm_tester',
			[ esdm_ipc_ns, 'es_pkcs11_softhsm_test.c' ],
			dependencies: dependencies_server,
			include_directories: include_dirs_server,
			link_with: esdm_static_lib,
		)
		test('ES PKCS11 with SoftHSM', es_pkcs11_softhsm_tester,
			timeout: 120)
	endif
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
