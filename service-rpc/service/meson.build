# for i in $(ls *.c | sort); do echo "'$i',"; done
service_rpc_src = files([
	'esdm_rpc_protocol.c',
	'priv_access.pb-c.c',
	'unpriv_access.pb-c.c',
])

if not get_option('small_memory')
	service_rpc_src += files([
		'esdm_rpc_protocol_helper.c',
	])
endif
