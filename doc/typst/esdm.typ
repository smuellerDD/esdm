#import "template.typ": *

#show: esdm-doc.with(
  title: [Entropy Source and DRNG Manager],
  author: [Stephan Müller \<smueller\@chronox.de\>],
  date: [ESDM 1.2.4 \ November 14, 2026],
  abstract: [
    Almost all parts of cryptography rest on a random number generator
    which produces data that are indistinguishable from a perfect generator.
    This also implies that the random number generator is seeded with
    sufficient entropy and the entropy is maintained during processing. Also
    a reseed at proper intervals is important to maintain the security
    strength. Finally, different users and use cases have different
    requirements regarding seeding and the deterministic processing. All
    these tasks are non-trivial in nature. The Entropy Source and DRNG
    Manager (ESDM) provides a flexible and extensible framework. The ESDM
    also provides a set of well-known interfaces: an API and ABI compliant
    drop-in replacement for Linux /dev/random, /dev/urandom and
    getrandom(2) system call as well as for an Entropy Gathering Daemon
    (EGD).
  ],
)

#include "chapters/01-introduction.typ"
#include "chapters/02-design.typ"
#include "chapters/03-irq-assessment.typ"
#include "chapters/04-sched-assessment.typ"
#include "chapters/05-configurations.typ"

#show: appendix
#include "chapters/appendix.typ"
