# SELinux Ruleset for `esdm-proc`

If you use SELinux in targeted mode (e.g. when using ESDM on Fedora), you need
to create the policy from the rule set in this directory. After installing
the SELinux policy development environment (e.g. by installing
`selinux-policy-devel` and `rpm-build`), perform the following steps:

1. Execute `esdm-proc.sh` which generates the SELinux policy file, loads it and
   generates an RPM package for later use. Note, the rule set defines in
   `esdm_proc.fc` the location of the executable `esdm-proc`. If the location
   on your system differs, update this entry before compiling.

2. After compiling and installing the policy, relabel `esdm-proc` by executing:
   `restorecon /usr/local/bin/esdm-proc`. On Fedora systems, you also need to
   relabel the other parts of ESDM in order to be usable by systemd:
   `restorecon /usr/local/bin/esdm-*`, `restorecon /usr/local/lib64/libesdm*`,
   `restorecon /usr/local/lib/systemd/system/esdm*`.

3. Reload systemd: `systemd daemon-reload`

4. Start the `esdm-proc` service which also loads `esdm-server`:
   `systemctl start esdm-proc`.
