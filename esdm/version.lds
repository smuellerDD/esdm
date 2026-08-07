/*
 * Linker version script for libesdm.
 *
 * The library is already compiled with -fvisibility=hidden, but a fair number
 * of symbols have to be marked DSO_PUBLIC so that they can be used across the
 * static convenience libraries the ESDM server is assembled from. Those
 * symbols then leak out of libesdm.so as well, even though they are not part
 * of the supported API.
 *
 * This script draws the line explicitly: LIBESDM_1.0 is the supported API as
 * declared by the installed headers esdm.h and esdm_config.h, everything an
 * in-tree consumer additionally needs lives in LIBESDM_PRIVATE_1.0, and
 * everything else is hidden.
 *
 * Both nodes together define the ABI - do not remove a symbol from
 * LIBESDM_1.0 or rename the node without bumping the library soversion. New
 * API is added in a new node (LIBESDM_1.1 { ... } LIBESDM_1.0;) so that
 * existing binaries keep binding to the version they were linked against.
 */

LIBESDM_1.0 {
	global:
		/* esdm.h - library life cycle */
		esdm_init;
		esdm_reinit;
		esdm_init_monitor;
		esdm_fini;

		/* esdm.h - random number generation */
		esdm_get_random_bytes;
		esdm_get_random_bytes_full;
		esdm_get_random_bytes_full_noblock;
		esdm_get_random_bytes_pr;
		esdm_get_random_bytes_pr_noblock;
		esdm_get_seed;

		/* esdm.h - status reporting */
		esdm_status;
		esdm_status_json;
		esdm_status_machine;
		esdm_version;
		esdm_state_operational;
		esdm_state_fully_seeded;
		esdm_sp80090c_compliant;
		esdm_ntg1_compliant;
		esdm_ntg1_2024_compliant;

		/* esdm.h - entropy pool handling */
		esdm_pool_insert_aux;
		esdm_pool_set_entropy;
		esdm_avail_entropy;
		esdm_avail_entropy_aux;
		esdm_avail_poolsize_aux;
		esdm_get_aux_ent;
		esdm_get_digestsize;
		esdm_drng_force_reseed;
		esdm_get_write_wakeup_bits;
		esdm_set_write_wakeup_bits;
		esdm_get_reseed_max_time;
		esdm_set_reseed_max_time;

		/* esdm_config.h - node handling */
		esdm_config_curr_node;
		esdm_config_max_nodes;
		esdm_config_max_nodes_set;
		esdm_config_online_nodes;

		/* esdm_config.h - DRNG management */
		esdm_config_drng_max_wo_reseed;
		esdm_config_drng_max_wo_reseed_bits;

		/* esdm_config.h - compliance settings */
		esdm_config_fips_enabled;
		esdm_config_force_fips_set;
		esdm_config_sp80090c_compliant;

		/* esdm_config.h - miscellaneous settings */
		esdm_config_ipc_cleanup;
		esdm_config_ipc_cleanup_set;

		/* esdm_config.h - entropy source settings */
		esdm_config_es_cpu_entropy_rate;
		esdm_config_es_cpu_entropy_rate_set;
		esdm_config_es_hwrand_entropy_rate;
		esdm_config_es_hwrand_entropy_rate_set;
		esdm_config_es_irq_ebpf_entropy_rate;
		esdm_config_es_irq_ebpf_entropy_rate_set;
		esdm_config_es_irq_entropy_rate;
		esdm_config_es_irq_entropy_rate_set;
		esdm_config_es_irq_retry;
		esdm_config_es_irq_retry_set;
		esdm_config_es_jent_async_enabled;
		esdm_config_es_jent_async_enabled_set;
		esdm_config_es_jent_entropy_rate;
		esdm_config_es_jent_entropy_rate_set;
		esdm_config_es_jent_kernel_entropy_rate;
		esdm_config_es_jent_kernel_entropy_rate_set;
		esdm_config_es_krng_entropy_rate;
		esdm_config_es_krng_entropy_rate_set;
		esdm_config_es_pkcs11_entropy_rate;
		esdm_config_es_pkcs11_entropy_rate_set;
		esdm_config_es_sched_ebpf_entropy_rate;
		esdm_config_es_sched_ebpf_entropy_rate_set;
		esdm_config_es_sched_entropy_rate;
		esdm_config_es_sched_entropy_rate_set;
		esdm_config_es_sched_retry;
		esdm_config_es_sched_retry_set;
		esdm_config_es_tpm2_entropy_rate;
		esdm_config_es_tpm2_entropy_rate_set;

	local:
		*;
};

/*
 * Not API: these are consumed by the ESDM server and the test suite, which
 * ship from this very tree and are therefore always in lockstep with the
 * library. They may change or disappear in any release - do not use them from
 * outside this project.
 */
LIBESDM_PRIVATE_1.0 {
	global:
		/* esdm_logger.h */
		_esdm_logger;
		esdm_logger_enable_syslog;
		esdm_logger_set_verbosity;

		/* esdm_es_jent.h */
		esdm_jent_status;

		/*
		 * esdm_es_pkcs11.h - the token configuration the server sets
		 * from its RPC handler. Only built when es_pkcs11 is enabled;
		 * the linker is asked for --undefined-version so naming them
		 * here costs nothing in a build without that source.
		 */
		esdm_es_pkcs11_set_pin;
		esdm_es_pkcs11_set_token_label;

		/* esdm_shm_status.h */
		esdm_shm_status_cleanup_ipc;

		/* threading_support.h */
		thread_get_name;
		thread_release;
		thread_set_name;
		thread_start;
		thread_wait_all;
} LIBESDM_1.0;
