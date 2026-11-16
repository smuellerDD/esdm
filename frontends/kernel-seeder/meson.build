# ESDM kernel seeder
esdm_kernel_seeder = executable(
		'esdm-kernel-seeder',
        [ 'seeder_main.c' ],
		include_directories: include_dirs_client,
		dependencies: [ dependencies_client ],
		link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ],
		install: true
		)

kernel_seeder_conf_data = configuration_data()
kernel_seeder_conf_data.set('PATH', get_option('prefix') + '/' + get_option('bindir'))
# Without systemd support the seeder never sends READY=1, so a notify unit would
# time out its start and fail esdm-linux-compat.target with it
kernel_seeder_conf_data.set('SERVICE_TYPE',
	get_option('systemd').enabled() ? 'Type=notify' : 'Type=exec')
esdm_kernel_seeder_service = configure_file(
	input : 'esdm-kernel-seeder.service.in',
	output : 'esdm-kernel-seeder.service',
	configuration : kernel_seeder_conf_data)
install_data(esdm_kernel_seeder_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
