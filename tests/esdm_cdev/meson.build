# The checks of the esdm_cdev kernel module (kernel/esdm_cdev), one subcommand
# of esdm-cdev-check each. They talk to the loaded module and the ESDM serving
# it, so they need neither a server of their own nor the test hooks - and they
# skip (77) where the module is not loaded, as in the build sandbox, or where
# they need privileges the run does not have.
#
# The NixOS VM test of the flake runs every one of them, the installed binary
# (option esdm-cdev-check), with the ESDM running, stopped and restarted, and
# drives the module against the fake EGD server of the binary. The ones that
# hold next to the ESDM of an ordinary machine are registered here:
#  * not ioctl-priv, which credits entropy nobody delivered and clears the
#    pool of that ESDM,
#  * not the checks of an ESDM that is not reachable (ioctl-unreachable,
#    proc-empty) or of the fake EGD server (fake-egd and the checks against
#    it), which take a module loaded for them,
#  * not the readers the VM test runs behind (loop, block) nor the
#    informational throughput.
esdm_cdev_check = executable(
	'esdm-cdev-check',
	[ 'esdm_cdev_check.c' ],
	include_directories: include_dirs_egd_client,
	dependencies: [ json_c_dep, dependency('threads') ],
	install: get_option('esdm-cdev-check').enabled(),
)

# The prediction resistance DRNG hands out what its entropy sources just
# delivered, which O_SYNC reads wait for.
test('esdm_cdev reads', esdm_cdev_check,
	args: [ 'reads' ],
	timeout: 120,
	suite: 'esdm_cdev')
test('esdm_cdev reads O_SYNC', esdm_cdev_check,
	args: [ 'reads', 'sync' ],
	timeout: 300,
	suite: 'esdm_cdev')
test('esdm_cdev O_NONBLOCK', esdm_cdev_check,
	args: [ 'nonblock' ],
	suite: 'esdm_cdev')
test('esdm_cdev poll', esdm_cdev_check,
	args: [ 'poll' ],
	suite: 'esdm_cdev')
test('esdm_cdev writes', esdm_cdev_check,
	args: [ 'writes' ],
	suite: 'esdm_cdev')

# As root, the check gives up CAP_SYS_ADMIN before it starts.
test('esdm_cdev unprivileged ioctls', esdm_cdev_check,
	args: [ 'ioctl-unpriv' ],
	suite: 'esdm_cdev')

# Root only: it sets write_wakeup_threshold and urandom_min_reseed_secs of
# the ESDM, and restores them.
test('esdm_cdev /proc/esdm', esdm_cdev_check,
	args: [ 'proc' ],
	suite: 'esdm_cdev')

# Root only, for a userfaultfd catching the faults of the kernel. Each of its
# requests next to the stalled writers has to be answered within 2 seconds,
# so it does not share the machine with the rest of the suite.
test('esdm_cdev stalled writers', esdm_cdev_check,
	args: [ 'stalled-writers' ],
	is_parallel: false,
	suite: 'esdm_cdev')
