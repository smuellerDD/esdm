# Client for the EGD interface of the ESDM. Deliberately dependency free
# beyond the ESDM logger: everything it needs is one Unix domain stream
# socket, which is what makes it usable where the RPC client is not.
egd_client_src = files([
	'esdm_egd_client.c'
])

esdm_egd_client_lib = both_libraries('esdm_egd_client',
	[ egd_client_src ],
	include_directories: include_dirs_egd_client,
	link_with: esdm_common_static_lib,
	version: meson.project_version(),
	soversion: version_array[0],
	install: true
	)
pkgconfig.generate(esdm_egd_client_lib)

include_user_files += files([
	'esdm_egd_client.h'
])
