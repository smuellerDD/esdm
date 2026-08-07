# Tests of the esdm-proc filesystem handlers.
#
# Mounting the filesystem needs root and /dev/fuse, but its handlers are
# ordinary functions of a path and a mode, so they are exercised directly. The
# translation unit is compiled into the test to reach them - they are all
# static - with its main() renamed out of the way.
if get_option('linux-devfiles').enabled()
	# proc_files.c reaches into the privilege helpers, and the SELinux
	# relabelling when that is compiled in.
	proc_files_test_extra_src = []
	if get_option('selinux').enabled()
		proc_files_test_extra_src += files('../../frontends/cuse/selinux.c')
	endif

	proc_files_test = executable(
			'proc_files_test',
			[ files('../../frontends/cuse/privileges.c'),
			  proc_files_test_extra_src,
			  'proc_files_test.c' ],
			c_args: [ '-Dmain=esdm_proc_main_unused' ],
			include_directories: [
				include_dirs_client,
				include_directories('../../frontends/cuse'),
				include_directories('../common') ],
			dependencies: [ dependencies_client, cuse_deps ],
			link_with: [ esdm_common_static_lib,
				     esdm_rpc_client_lib ],
		)

	test('esdm-proc file handlers', proc_files_test)
endif
