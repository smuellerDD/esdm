/*
 * Linker version script for libesdm_es_ext - the API of esdm_es_ext.h. The
 * protocol helpers of esdm_es_ext_proto.h are static inline, and neither the
 * command line of a provider program behind esdm_es_ext_provider_main() -
 * esdm_es_ext_provider.h, which the programs of the ESDM reach in the static
 * library - nor the common code the library is linked with is exported.
 */

LIBESDM_ES_EXT_1.0 {
	global:
		esdm_es_ext_provider_main;
		esdm_es_ext_server_alloc;
		esdm_es_ext_server_allow_uid;
		esdm_es_ext_server_free;
		esdm_es_ext_server_run;
		esdm_es_ext_server_set_entropy_rate;
		esdm_es_ext_server_set_name;
		esdm_es_ext_server_stop;

	local:
		*;
};
