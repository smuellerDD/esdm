# Raw entropy measurement tool for the eBPF entropy sources - built only
# with -Des_ebpf_testing=enabled, never for production deployments.

esdm_ebpf_collect = executable(
	'esdm-ebpf-collect',
	[ 'esdm_ebpf_collect.c', esdm_ebpf_skel_hdrs ],
	dependencies: [ libbpf_dep ],
	include_directories: [ include_dirs_server, include_dirs_esdm_ebpf ],
)
