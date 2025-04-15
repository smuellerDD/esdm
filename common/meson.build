# for i in $(ls *.c | sort); do echo "'$i',"; done
common_src = files([
	'binhexbin.c',
	'buffer.c',
	'esdm_logger.c',
	'helper.c',
	'threading_support.c',
])

if get_option('testmode').enabled()
	common_src += files(['test_pertubation.c'])
endif

if host_machine.system() == 'linux'
	common_src += files('linux_support.c')
endif

conf_data = configuration_data()

conf_data.set('ESDM_OVERSAMPLE_ENTROPY_SOURCES',
	      get_option('sp80090c') or get_option('fips140'))
conf_data.set('ESDM_AIS2031_NTG1_SEEDING_STRATEGY', get_option('ais2031'))
if get_option('sp80090c') or get_option('fips140')
	conf_data.set('ESDM_SEED_BUFFER_INIT_ADD_BITS', 128)
	conf_data.set('ESDM_OVERSAMPLE_ES_BITS', 64)
else
	conf_data.set('ESDM_SEED_BUFFER_INIT_ADD_BITS', 0)
	conf_data.set('ESDM_OVERSAMPLE_ES_BITS', 0)
endif

if get_option('crypto_backend') == 'builtin'
	conf_data.set('ESDM_DRNG_HASH_DRBG', get_option('drng_hash_drbg').enabled())
	conf_data.set('ESDM_DRNG_CHACHA20', get_option('drng_chacha20').enabled())
	conf_data.set('ESDM_HASH_SHA512', get_option('hash_sha512').enabled())
	conf_data.set('ESDM_HASH_SHA3_512', get_option('hash_sha3_512').enabled())
else
	conf_data.set('ESDM_DRNG_HASH_DRBG', false)
	conf_data.set('ESDM_DRNG_CHACHA20', false)
	conf_data.set('ESDM_HASH_SHA512', false)
	conf_data.set('ESDM_HASH_SHA3_512', false)
endif

if get_option('crypto_backend') == 'gnutls'
	conf_data.set('ESDM_GNUTLS', true)
else
	conf_data.set('ESDM_GNUTLS', false)
endif

if get_option('crypto_backend') == 'leancrypto'
	conf_data.set('ESDM_LEANCRYPTO', true)
else
	conf_data.set('ESDM_LEANCRYPTO', false)
endif

if get_option('crypto_backend') == 'openssl'
	conf_data.set('ESDM_OPENSSL', true)
else
	conf_data.set('ESDM_OPENSSL', false)
endif

if get_option('crypto_backend') == 'botan'
	conf_data.set('ESDM_BOTAN', true)
else
	conf_data.set('ESDM_BOTAN', false)
endif

conf_data.set('ESDM_OPENSSL_DRNG_CTR', get_option('openssl_drng_type') == 'ctr')
conf_data.set('ESDM_OPENSSL_DRNG_HASH', get_option('openssl_drng_type') == 'hash')
conf_data.set('ESDM_OPENSSL_DRNG_HMAC', get_option('openssl_drng_type') == 'hmac')

conf_data.set('ESDM_BOTAN_DRNG_CHACHA20', get_option('botan_drng_type') == 'chacha20')
conf_data.set('ESDM_BOTAN_DRNG_HMAC', get_option('botan_drng_type') == 'hmac')

# This option currently is not configurable!
conf_data.set('CONFIG_ESDM_USE_PTHREAD', true)
conf_data.set('THREADING_MAX_THREADS', get_option('threading_max_threads'))

conf_data.set('ESDM_ES_JENT', get_option('es_jent').enabled())
conf_data.set('ESDM_JENT_ENTROPY_RATE',
	      get_option('es_jent_entropy_rate'))

# In esdm_es_jent.c the ESDM_JENT_ENTROPY_BLOCKS are divided by 4 and yet
# need to result in a value larger than zero
if get_option('es_jent_entropy_blocks') >= 4
	conf_data.set('ESDM_JENT_ENTROPY_BLOCKS',
		      get_option('es_jent_entropy_blocks'))
else
	conf_data.set('ESDM_JENT_ENTROPY_BLOCKS', 0)
endif

conf_data.set('ESDM_ES_CPU', get_option('es_cpu').enabled())
conf_data.set('ESDM_CPU_ENTROPY_RATE',
	      get_option('es_cpu_entropy_rate'))
conf_data.set('ESDM_CPU_FULL_ENT_MULTIPLIER',
	      get_option('es_cpu_multiplier'))

conf_data.set('ESDM_ES_IRQ', get_option('es_irq').enabled())
conf_data.set('ESDM_IRQ_ENTROPY_RATE',
	      get_option('es_irq_entropy_rate'))

conf_data.set('ESDM_ES_KERNEL_RNG', get_option('es_kernel').enabled())
conf_data.set('ESDM_KERNEL_RNG_ENTROPY_RATE',
	      get_option('es_kernel_entropy_rate'))

conf_data.set('ESDM_ES_SCHED', get_option('es_sched').enabled())
conf_data.set('ESDM_SCHED_ENTROPY_RATE',
	      get_option('es_sched_entropy_rate'))

conf_data.set('ESDM_ES_HWRAND', get_option('es_hwrand').enabled())
conf_data.set('ESDM_HWRAND_ENTROPY_RATE',
	      get_option('es_hwrand_entropy_rate'))

conf_data.set('ESDM_ES_JENT_KERNEL', get_option('es_jent_kernel').enabled())
conf_data.set('ESDM_JENT_KERNEL_ENTROPY_RATE',
	      get_option('es_jent_kernel_entropy_rate'))

if (get_option('es_irq_entropy_rate') > 0) and get_option('es_sched_entropy_rate') > 0
	error('It is not permissible to award both, the interrupt and scheduler-based entropy sources, an entropy rate greater than zero. Adjust es_irq_entropy_rate or es_sched_entropy_rate to zero.')
endif

conf_data.set('ESDM_SELINUX_ENABLED', get_option('selinux').enabled())
conf_data.set('ESDM_NODE', get_option('node').enabled())
conf_data.set('ESDM_FIPS140', get_option('fips140'))

conf_data.set('ESDM_CLIENT_CONNECT_TIMEOUT_EXPONENT', get_option('client-connect-timeout-exponent'))
conf_data.set('ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT', get_option('client-rx-tx-timeout-exponent'))
conf_data.set('ESDM_CLIENT_RECONNECT_ATTEMPTS', get_option('client-reconnect-attempts'))

conf_data.set('ESDM_WORKERLOOP_TERM_ON_SIGNAL', get_option('esdm-server-term-on-signal'))

conf_data.set('ESDM_TESTMODE', get_option('testmode').enabled())

if build_machine.system() == 'linux'
	conf_data.set('ESDM_LINUX', 1)
endif

conf_data.set('ESDM_RPCC_BUF_WRITE', not get_option('small_memory'))
conf_data.set('ESDM_RPCS_BUF_WRITE', not get_option('small_memory'))

conf_data.set('ESDM_GETRANDOM_NUM_NODES', get_option('linux-getrandom-num-nodes'))

conf_data.set('ESDM_LINUX_RESEED_INTERVAL_SEC', get_option('linux-reseed-interval'))
conf_data.set('ESDM_LINUX_RESEED_ENTROPY_COUNT', get_option('linux-reseed-entropy-count'))

conf_data.set('ESDM_DRNG_RESEED_THRESH_BITS', get_option('drng_reseed_threshold_bits'))
conf_data.set('ESDM_DRNG_MAX_RESEED_BITS', get_option('drng_max_reseed_bits'))

conf_data.set_quoted('ESDM_SERVER_RPC_BASE_PATH_UNPRIVILEGED', get_option('esdm-server-rpc-path-unprivileged'))
conf_data.set_quoted('ESDM_SERVER_RPC_BASE_PATH_PRIVILEGED', get_option('esdm-server-rpc-path-privileged'))

conf_data.set('ESDM_RPC_IDLE_TIMEOUT_USEC', get_option('esdm-server-rpc-idle-timeout-usec'))

conf_data.set('ESDM_HAS_AUX_CLIENT', get_option('esdm-aux-client').enabled())

conf_data.set('ESDM_NUM_AUX_POOLS', get_option('num-aux-pools'))

configure_file(output: 'config.h', configuration : conf_data)
