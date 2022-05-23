accessd rtadv PoC branch
========================

This is a **proof of concept** branch for rtadv in a separate daemon, and
creating link-local addresses per RA prefix advertisement.

The code here is **not done**.  A lot of cleanup is missing, i.e. there are
memory leaks and addresses are not deleted after use.

How to use
----------

1. build according to regular build instructions under doc/developer/build...
   (don't install into system, not needed & not tested)

2. remove any existing FRR configuration

3. start zebra:  `sudo zebra/zebra --log stdout --log-level debug -t`  (this
   will run in foreground with logs and an open terminal session.)

4. start accessd:  `sudo accessd/accessd --log stdout --log-level debug -t`
   (again, runs in foreground with logs and terminal session.)

5. on the accessd terminal session, configure IPv6 RA with:
   ```
   configure
   interface XYZ
   no ipv6 nd suppress-ra
   ipv6 nd prefix 2001:db8:1234:5678::/64 dad-lladdr
   ipv6 nd prefix 2001:db8:2345:6789::/64 dad-lladdr
   ```

6. you should see a message like this:
```
2022/05/23 09:32:33 ACCESSD: [YR33T-VY7T0] LL for 2001:db8:1234:5678::/64: fe80::35a5:7fa5:a554:cc81
```

The LL addr is based on sha256 of the prefix + the router's MAC address on
the interface, so it'll stay consistent.  No attempts are made to somehow
resolve duplicate addresses.

On the highest byte of the IID (`fe80::X...:....:....:....`), bit 0 is always
set and bit 1 is always cleared. Because bit 0 is always set, it won't collide
with manual LL addrs like `fe80::1`.


Known issues
------------

- the LL addrs added for prefix advertisements may also be used for other
  things.  Specifically, the code sends a RA without prefixes too, but that
  might wrongly be sent with one of the "special" prefix LL addrs.
- the LL addr will not be deleted after the prefix advertisement is removed.
  You need to remove it manually with `ip addr del fe80::ABCD dev XYZ`
- the RA config is NOT displayed under `show running-config`.  You need to
  configure "blind".
- removing anything from the config will probably lead to crashes from missing
  cleanup.  Just restart accessd, the config isn't saved anyway, and you can
  add back a subset of the same prefixes.
- a bunch of RA config options are broken.  RDNSS/DNSSL are missing.
- there's memory leaks all around.
- the entire thing is a giant hack done in 2 days and will probably crash
  randomly.
- the RA code in zebra is still there and uses the same commands.  Don't use
  `vtysh`, it will configure `zebra` instead of `accessd`.
