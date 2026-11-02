{
  lib,
  ...
}:

[
  {
    name = "kasan_leak_check";
    patch = null;
    structuredExtraConfig = with lib.kernel; {
      DEBUG_KMEMLEAK = yes;
      DEBUG_KMEMLEAK_AUTO_SCAN = yes;

      KASAN = yes;
      KASAN_GENERIC = yes;
      KASAN_INLINE = yes;

      DEBUG_INFO = yes;
      STACKTRACE = yes;

      DEBUG_VM = yes;
      DEBUG_OBJECTS = yes;
      DEBUG_OBJECTS_FREE = yes;
      DEBUG_LOCK_ALLOC = yes;
      DEBUG_MUTEXES = yes;
      DEBUG_SPINLOCK = yes;
      DEBUG_RWSEMS = yes;
      DEBUG_WW_MUTEX_SLOWPATH = yes;

      PAGE_OWNER = yes;
      PAGE_POISONING = yes;

      LOCKDEP = yes;
      PROVE_LOCKING = yes;
      DEBUG_LOCKDEP = yes;

      DETECT_HUNG_TASK = yes;
      WQ_WATCHDOG = yes;

      PROVE_RCU = yes;
      DEBUG_OBJECTS_RCU_HEAD = yes;

      LOCK_STAT = yes;
      DEBUG_ATOMIC_SLEEP = yes;
    };
  }
]
