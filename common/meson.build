# for i in $(ls *.c | sort); do echo "'$i',"; done
common_src = files([
	'binhexbin.c',
	'buffer.c',
	'helper.c',
	'logger.c',
	'threading_support.c',
])

if get_option('testmode').enabled()
	common_src += files(['test_pertubation.c'])
endif

conf_data = configuration_data()

conf_data.set('ESDM_OVERSAMPLE_ENTROPY_SOURCES',
	      get_option('oversample_es'))
if get_option('oversample_es')
	conf_data.set('ESDM_SEED_BUFFER_INIT_ADD_BITS', 128)
	conf_data.set('ESDM_OVERSAMPLE_ES_BITS', 64)
else
	conf_data.set('ESDM_SEED_BUFFER_INIT_ADD_BITS', 0)
	conf_data.set('ESDM_OVERSAMPLE_ES_BITS', 0)
endif

conf_data.set('ESDM_DRNG_HASH_DRBG', get_option('drng_hash_drbg').enabled())
conf_data.set('ESDM_DRNG_CHACHA20', get_option('drng_chacha20').enabled())
conf_data.set('ESDM_HASH_SHA512', get_option('hash_sha512').enabled())
conf_data.set('ESDM_HASH_SHA3_512', get_option('hash_sha3_512').enabled())

# This option currently is not configurable!
conf_data.set('CONFIG_ESDM_USE_PTHREAD', true)
conf_data.set('THREADING_MAX_THREADS', get_option('threading_max_threads'))

conf_data.set('ESDM_ES_JENT', get_option('es_jent').enabled())
conf_data.set('ESDM_JENT_ENTROPY_RATE',
	      get_option('es_jent_entropy_rate'))

conf_data.set('ESDM_ES_CPU', get_option('es_cpu').enabled())
conf_data.set('ESDM_CPU_ENTROPY_RATE',
	      get_option('es_cpu_entropy_rate'))
conf_data.set('ESDM_CPU_FULL_ENT_MULTIPLIER',
	      get_option('es_cpu_multiplier'))

# This option currently is not configurable as the IRQ ES is not provided
conf_data.set('ESDM_ES_IRQ', false)

conf_data.set('ESDM_ES_KERNEL_RNG', get_option('es_kernel').enabled())
conf_data.set('ESDM_KERNEL_RNG_ENTROPY_RATE',
	      get_option('es_kernel_entropy_rate'))

conf_data.set('ESDM_ES_SCHED', get_option('es_sched').enabled())
conf_data.set('ESDM_SCHED_ENTROPY_RATE',
	      get_option('es_sched_entropy_rate'))

conf_data.set('ESDM_SELINUX_ENABLED', get_option('selinux').enabled())
conf_data.set('ESDM_NODE', get_option('node').enabled())
conf_data.set('ESDM_FIPS140', get_option('fips140').enabled())

conf_data.set('ESDM_TESTMODE', get_option('testmode').enabled())

configure_file(output: 'config.h', configuration : conf_data)
