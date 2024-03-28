# for i in $(ls *.c | sort); do echo "'$i',"; done
server_rpc_src = files([
	'esdm_rpc_get_ent_lvl_s.c',
	'esdm_rpc_get_min_reseed_secs_s.c',
	'esdm_rpc_get_poolsize_s.c',
	'esdm_rpc_get_random_bytes_full_s.c',
	'esdm_rpc_get_random_bytes_min_s.c',
	'esdm_rpc_get_random_bytes_pr_s.c',
	'esdm_rpc_get_random_bytes_s.c',
	'esdm_rpc_get_seed_s.c',
	'esdm_rpc_get_write_wakeup_thresh_s.c',
	'esdm_rpc_is_fully_seeded_s.c',
	'esdm_rpc_is_min_seeded_s.c',
	'esdm_rpc_rnd_add_entropy_s.c',
	'esdm_rpc_rnd_add_to_ent_cnt_s.c',
	'esdm_rpc_rnd_clear_pool_s.c',
	'esdm_rpc_rnd_get_ent_cnt_s.c',
	'esdm_rpc_rnd_reseed_crng_s.c',
	'esdm_rpc_server.c',
	'esdm_rpc_service.c',
	'esdm_rpc_set_min_reseed_secs_s.c',
	'esdm_rpc_set_write_wakeup_thresh_s.c',
	'esdm_rpc_status_s.c',
	'esdm_rpc_write_data_s.c',
	'privileges.c'
])

if get_option('es_irq').enabled()
	server_rpc_src += files('esdm_rpc_server_linux.c')
endif
