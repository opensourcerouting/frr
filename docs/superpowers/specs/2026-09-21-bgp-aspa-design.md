# ASPA support in FRR bgpd

Date: 2026-09-21
Branch: `feature/bgp_aspa`
Status: approved design, not yet implemented

## 1. Goal

Add ASPA (Autonomous System Provider Authorization, RFC 9234-adjacent,
`draft-ietf-sidrops-aspa-verification`) AS_PATH verification to bgpd's RPKI
module, using the ASPA support that now exists in librtr (rtrlib).

Scope is deliberately the same shape as the existing RPKI origin validation
support: compute a validation state, expose it to route-maps and to `show`
commands, and let the operator decide policy. No built-in accept/reject
behaviour.

## 2. Background: what rtrlib gives us

ASPA landed in rtrlib **after** the v0.8.0 release and is only on `master`.

### 2.1 Public ASPA API

From `rtrlib/aspa/aspa.h` and `rtrlib/rtr_mgr.h`:

```c
struct rtr_aspa_record {
	uint32_t customer_asn;
	size_t   provider_count;
	uint32_t *provider_asns;
};

enum rtr_aspa_operation_type { RTR_ASPA_REMOVE = 0, RTR_ASPA_ADD = 1 };

typedef void (*rtr_aspa_update_fp)(struct rtr_aspa_table *aspa_table,
				   const struct rtr_aspa_record record,
				   const struct rtr_socket *rtr_socket,
				   const enum rtr_aspa_operation_type operation_type);

enum rtr_aspa_direction { RTR_ASPA_UPSTREAM, RTR_ASPA_DOWNSTREAM };

enum rtr_aspa_verification_result {
	RTR_ASPA_AS_PATH_UNKNOWN,
	RTR_ASPA_AS_PATH_INVALID,
	RTR_ASPA_AS_PATH_VALID,
};

enum rtr_aspa_status rtr_mgr_aspa_validate(struct rtr_mgr_config *config,
					   uint32_t as_path[], size_t len,
					   enum rtr_aspa_direction direction,
					   enum rtr_aspa_verification_result *result);

enum rtr_rtvals rtr_mgr_add_aspa_support(struct rtr_mgr_config *config,
					 const rtr_aspa_update_fp aspa_update_fp);
```

Two properties of `rtr_mgr_aspa_validate()` matter for the AS_PATH conversion
in section 6:

- **Ordering.** `aspa_verify_as_path_upstream()` documents "the origin AS has
  index N - 1 and the latest AS in the AS_PATH has index 0". That is the same
  left-to-right order as a BGP AS_PATH, so no reversal is needed.
- **The local ASN is excluded.** The header says "the AS path to validate
  (without the AS of the current router)". A received eBGP AS_PATH already
  satisfies this.
- **Prepending is handled by rtrlib.** `aspa_check_hop()` returns
  `ASPA_PROVIDER_PLUS` when `customer_asn == provider_asn`, so FRR must *not*
  de-duplicate prepends itself.

### 2.2 The API rename

The same unreleased window contains commit `f3d1cfa "rtrlib: Make API
consistent"`, which prefixed the entire public API with `rtr_`. There are no
compatibility aliases. Symbols that bgpd uses today and that changed:

| rtrlib v0.8.0 (current FRR) | rtrlib master |
| --- | --- |
| `struct pfx_record` | `struct rtr_pfx_record` |
| `struct pfx_table` | `struct rtr_pfx_table` |
| `enum pfxv_state` | `enum rtr_pfxv_state` |
| `PFX_SUCCESS` | `RTR_PFX_SUCCESS` |
| `BGP_PFXV_STATE_VALID` / `_NOT_FOUND` / `_INVALID` | `RTR_BGP_PFXV_STATE_*` |
| `pfx_table_for_each_ipv4_record` / `_ipv6_` | `rtr_pfx_table_for_each_ipv4_record` / `_ipv6_` |
| `pfx_table_validate_r` | `rtr_pfx_table_validate_r` |
| `pfx_update_fp` | `rtr_pfx_update_fp` |
| `rtr_mgr_validate` | `rtr_mgr_roa_validate` |
| `struct lrtr_ip_addr` | `struct rtr_ip_addr` |
| `LRTR_IPV4` / `LRTR_IPV6` | `RTR_IPV4` / `RTR_IPV6` |
| `struct tr_socket` | `struct rtr_tr_socket` |
| `struct tr_tcp_config` / `tr_ssh_config` | `struct rtr_tr_tcp_config` / `rtr_tr_ssh_config` |
| `tr_tcp_init` / `tr_ssh_init` | `rtr_tr_tcp_init` / `rtr_tr_ssh_init` |
| `rtr_mgr_init(...)` | different signature, see 4.2 |

`struct rtr_socket`, `struct rtr_mgr_config`, `struct rtr_mgr_group`,
`RTR_SUCCESS`, `RTR_ERROR`, `RTR_ESTABLISHED`, `rtr_mgr_start/stop/free/
add_group/remove_group/conf_in_sync/get_first_group` are unchanged.

**Struct member names did not change.** `struct rtr_socket` still has a member
literally called `tr_socket`, and still has `pfx_table`. This rules out the
obvious shim direction; see section 4.1.

### 2.3 rtrlib master still reports version 0.8.0

`CMakeLists.txt` on master has not bumped `RTRLIB_VERSION_*`, so
`pkg-config --modversion rtrlib` returns `0.8.0` for both the released library
and the ASPA-capable master. A version-based `PKG_CHECK_MODULES` test therefore
**cannot** distinguish them. Detection must be a symbol/link test.

### 2.4 RTR protocol version

`rtr_init()` sets `rtr_socket->version = RTR_PROTOCOL_MAX_SUPPORTED_VERSION`,
which is `2` on master, and rtrlib negotiates downward if the cache is older.
ASPA PDUs require RTR version 2. No FRR-side version selection work is needed.

### 2.5 No ASPA table iteration API

`aspa.h` exposes only `init` / `free` / `src_remove` / `verify`. The
`struct rtr_aspa_table` field `store` is a `struct aspa_store_node *`, and
`aspa_store_node` is declared only in `aspa_private.h`, which rtrlib's
`CMakeLists.txt` explicitly excludes from installation (`NOT ${ITEM} MATCHES
".*_private\\.h"`). The validated ASPA set therefore **cannot be read back out
of rtrlib**. This is the sole reason for the shadow table in section 5.

### 2.6 Initialisation ordering trap

`rtr_mgr_init()` allocates its config with `rtr_malloc()`, which is plain
`malloc()`, and then assigns only `len`, `mutex`, `status_fp`,
`status_fp_data`, `processing_thread_event_callback` and its data. It leaves
`config->pfx_table`, `config->spki_table` and `config->aspa_table`
**uninitialised**.

`rtr_mgr_setup_sockets()` calls `rtr_mgr_init_sockets()`, which reads all three
and passes them to `rtr_init()`, which stores them verbatim into every
`rtr_socket`.

Consequences, both of which the implementation must respect:

1. The `rtr_mgr_add_*_support()` calls must happen **before**
   `rtr_mgr_setup_sockets()`, not after.
2. All three of `rtr_mgr_add_roa_support()`, `rtr_mgr_add_aspa_support()` and
   `rtr_mgr_add_spki_support()` must be called, even though bgpd has no use for
   router keys. Skipping the spki one leaves a garbage pointer in every socket,
   which the RTR PDU handler will dereference if a Router Key PDU ever arrives.

This is arguably an rtrlib bug and is worth reporting upstream separately, but
FRR should not depend on it being fixed.

### 2.7 The ASPA update callback owns provider_asns

`aspa_table_notify_clients()` allocates a **fresh copy** of `provider_asns`
for every notification and never frees it:

```c
rec.provider_asns = rtr_malloc(size);
memcpy(rec.provider_asns, record->provider_asns, size);
aspa_table->update_fp(aspa_table, rec, rtr_socket, operation_type);
/* never freed */
```

Nothing in `aspa.h` documents this, but rtrlib's own `rtrclient` ends its ASPA
callback with `free(record.provider_asns)`, so the intended contract is that
the callback takes ownership. (rtrclient itself leaks it on its early-return
path, which is presumably an oversight.)

Two consequences for bgpd:

1. The callback must free `record.provider_asns` on **every** path, including
   ADD and REMOVE and every early return. Missing this leaks one allocation
   per notification — and because `rtr_mgr_free()` calls
   `rtr_aspa_table_free(table, notify=true)`, every record is notified a
   second time at shutdown, so the leak is two allocations per record.
2. It must be freed through the allocator rtrlib was given
   (`rtr_set_alloc_functions`), i.e. bgpd's `free_wrapper()`, not a plain
   `XFREE` of some unrelated MTYPE. Otherwise FRR's per-MTYPE accounting goes
   wrong even though the memory is released.

Because ownership transfers, bgpd passes the array straight to the main thread
rather than making a second copy of it.

This leak is invisible to AddressSanitizer in a standalone rtrlib program —
the memory really is freed there because no callback is registered — and shows
up only as an FRR memory-leak report at daemon shutdown.

## 3. Design decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| rtrlib version support | Build against both 0.8.0 and master | Every distro ships 0.8.0; FRR's RPKI module must not stop building. |
| Direction selection | Stated in the route-map, BIRD model | Keeps ASPA free of RFC 9234 OTC and Role-capability side effects. See 3.1. |
| Policy | Route-map only, no built-in reject | Matches existing RPKI origin validation in FRR. |
| Validation state storage | Computed on demand, not cached on the path | Matches `rpki_validate_prefix()`. |

### 3.1 Why the direction is not derived from `local-role`

ASPA verification has two variants and picking the wrong one produces a wrong
verdict:

- **Upstream** — route received from a customer, lateral peer, or RS-client.
  The AS_PATH must be a pure customer-to-provider up-ramp.
- **Downstream** — route received from a provider or an RS. The AS_PATH may be
  up-ramp + apex + down-ramp, a strictly weaker test.

So the verifier must know its business relationship with the sending neighbor.
FRR already encodes exactly that in RFC 9234 `neighbor X local-role`, with
exactly the five values ASPA needs, and OpenBGPD couples the two deliberately:
its manual states "Setting a role is required for ASPA verification, the open
policy role capability and Only-To-Customer (OTC) attribute of RFC 9234."

FRR does not adopt that coupling, because in FRR setting `local-role` also
switches on OTC route-leak handling (`bgp_otc_filter()` /`bgp_otc_egress()` in
`bgpd/bgp_route.c`, both gated on `PEER_FLAG_ROLE`) and advertises the Role
capability in OPEN. An operator who wants ASPA would be forced into a change in
route propagation behaviour they did not ask for.

Instead FRR follows BIRD, whose `aspa_check_upstream()` /
`aspa_check_downstream()` are chosen per filter. FRR's equivalent of a BIRD
filter is the route-map, so the direction becomes part of the match:

```
match aspa <upstream|downstream> <valid|invalid|unknown>
```

`peer->local_role` is never consulted. The cost is that operators already
running RFC 9234 restate the relationship in the route-map and must keep the
two consistent; the benefit is that ASPA and OTC are independently adoptable.

### 3.2 Accepted trade-offs

- **`match aspa` parses on builds without ASPA support.** The yang model and
  northbound callbacks are compiled unconditionally, because a yang model must
  not vary with module availability, while the match handler lives in the
  loadable rpki module. On a build without `FOUND_ASPA`, or with the module not
  loaded, `match aspa` is accepted by the parser and never matches. This is
  exactly how `match rpki` behaves today, so it is consistent rather than new.
- **ASPA state is absent from full-table `show bgp` output.** See section 8.

## 4. Build plumbing and the compatibility layer

### 4.1 Direction of the shim

The naive shim maps old names onto new ones
(`#define pfx_table rtr_pfx_table`) so that `bgp_rpki.c` need not change. **This
cannot work.** `#define tr_socket rtr_tr_socket` is a token substitution and
would also rewrite the member accesses `cache->tr_socket` and
`rtr_socket->tr_socket`, because rtrlib kept those member names (2.2).

The mapping therefore goes the other way:

- `bgp_rpki.c` is ported to the **new** (rtrlib master) spellings.
- A new header `bgpd/bgp_rpki_compat.h` maps new to old when the new API is
  *not* present.

Every new-API token (`rtr_pfx_*`, `rtr_tr_*`, `rtr_ip_addr`, `RTR_IPV4`,
`RTR_BGP_PFXV_STATE_*`, `rtr_mgr_roa_validate`) is distinct from anything FRR or
old rtrlib declares, and none of them collide with a struct member name, so the
substitution is safe in this direction.

```c
/* bgpd/bgp_rpki_compat.h */
#ifndef FOUND_ASPA          /* rtrlib < 0.9 spellings */
#define rtr_pfx_record                     pfx_record
#define rtr_pfx_table                      pfx_table
#define rtr_pfx_rtvals                     pfx_rtvals
#define rtr_pfx_update_fp                  pfx_update_fp
#define RTR_PFX_SUCCESS                    PFX_SUCCESS
#define rtr_pfxv_state                     pfxv_state
#define RTR_BGP_PFXV_STATE_VALID           BGP_PFXV_STATE_VALID
#define RTR_BGP_PFXV_STATE_NOT_FOUND       BGP_PFXV_STATE_NOT_FOUND
#define RTR_BGP_PFXV_STATE_INVALID         BGP_PFXV_STATE_INVALID
#define rtr_pfx_table_validate_r           pfx_table_validate_r
#define rtr_pfx_table_for_each_ipv4_record pfx_table_for_each_ipv4_record
#define rtr_pfx_table_for_each_ipv6_record pfx_table_for_each_ipv6_record
#define rtr_mgr_roa_validate               rtr_mgr_validate
#define rtr_ip_addr                        lrtr_ip_addr
#define RTR_IPV4                           LRTR_IPV4
#define RTR_IPV6                           LRTR_IPV6
#define rtr_tr_socket                      tr_socket
#define rtr_tr_tcp_config                  tr_tcp_config
#define rtr_tr_ssh_config                  tr_ssh_config
#define rtr_tr_tcp_init                    tr_tcp_init
#define rtr_tr_ssh_init                    tr_ssh_init
#endif
```

Included from `bgp_rpki.c` immediately after `rtrlib/rtrlib.h`.

The exact list is to be finalised against the compiler; the port is mechanical
and the build is the arbiter.

### 4.2 `rtr_mgr_init()` changed shape, not just name

A macro cannot express this, and there is exactly one call site (`start()` in
`bgp_rpki.c`), so it gets a small wrapper with two bodies. Note the ordering
required by 2.6:

```c
static int rpki_rtr_mgr_init(struct rpki_vrf *rpki_vrf,
			     struct rtr_mgr_group *groups, int groups_len)
{
#ifdef FOUND_ASPA
	int ret;

	ret = rtr_mgr_init(&rpki_vrf->rtr_config, groups, groups_len,
			   NULL, NULL, NULL, NULL);
	if (ret != RTR_SUCCESS)
		return ret;

	/* Must precede rtr_mgr_setup_sockets(): the tables are copied into
	 * every rtr_socket there, and rtr_mgr_init() leaves them
	 * uninitialised.
	 */
	rtr_mgr_add_roa_support(rpki_vrf->rtr_config, rpki_update_cb_sync_rtr);
	rtr_mgr_add_spki_support(rpki_vrf->rtr_config, NULL);
	rtr_mgr_add_aspa_support(rpki_vrf->rtr_config,
				 rpki_aspa_update_cb_sync_rtr);

	return rtr_mgr_setup_sockets(rpki_vrf->rtr_config, groups, groups_len,
				     rpki_vrf->polling_period,
				     rpki_vrf->expire_interval,
				     rpki_vrf->retry_interval);
#else
	return rtr_mgr_init(&rpki_vrf->rtr_config, groups, groups_len,
			    rpki_vrf->polling_period,
			    rpki_vrf->expire_interval,
			    rpki_vrf->retry_interval,
			    rpki_update_cb_sync_rtr, NULL, NULL, NULL);
#endif
}
```

### 4.3 configure.ac

Keep `PKG_CHECK_MODULES([RTRLIB], [rtrlib >= 0.8.0])` as-is. Because of 2.3 the
version tells us nothing, so add a link test alongside the existing `FOUND_SSH`
probe, with `RTRLIB_CFLAGS` / `RTRLIB_LIBS` in scope:

```m4
AC_MSG_CHECKING([whether the RTR Library supports ASPA])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include "rtrlib/rtrlib.h"
                                  #include "rtrlib/aspa/aspa.h"]],
		[[rtr_mgr_add_aspa_support(NULL, NULL);]])],
	[AC_MSG_RESULT([yes])
	 AC_DEFINE([FOUND_ASPA], [1], [found_aspa])],
	AC_MSG_RESULT([no])
)
```

`rtrlib/rtrlib.h` does not pull in `aspa.h`, hence the second include.

## 5. ASPA table state and revalidation

### 5.1 Shadow table (optional)

Because of 2.5, bgpd keeps its own copy of the validated ASPA set, per
`rpki_vrf`, purely so `show rpki aspa` can work. Validation itself always uses
rtrlib's table via `rtr_mgr_aspa_validate()`; the shadow copy is never consulted
for correctness.

```c
struct rpki_aspa_record {
	uint32_t customer_asn;
	size_t   provider_count;
	uint32_t *providers;    /* sorted, owned by this struct */
};
```

Stored in a `struct hash *aspa_table` on `struct rpki_vrf`, keyed by
`customer_asn`. New `MTYPE_BGP_RPKI_ASPA`. Freed in `stop()` alongside
`rtr_mgr_free()`.

This is the largest single piece of new code and is **optional**: `match aspa`,
validation, and the revalidation in 5.3 all work without it. If it is dropped,
`show rpki aspa` is dropped with it and nothing else changes. The socketpair in
5.2 is still required either way, because 5.3 needs it.

### 5.2 Cross-thread plumbing

The existing sync socketpair carries fixed-size `struct rtr_pfx_record` values
and is drained by `bgpd_sync_callback()`. ASPA records are variable-length, so
they need their own channel rather than a tagged union on the existing one.

Per `rpki_vrf`, add `rpki_aspa_sync_socket_rtr` / `_bgpd` and a message:

```c
struct rpki_aspa_msg {
	uint32_t customer_asn;
	size_t   provider_count;
	uint32_t *providers;    /* heap, transferred to the reader */
	bool     added;
};
```

`rpki_aspa_update_cb_sync_rtr()` runs on the rtrlib thread. rtrlib passes
`struct rtr_aspa_record` **by value** and owns `provider_asns`, freeing it after
the callback returns, so the callback must deep-copy the provider array before
writing the message. The pointer is passed through the socketpair, which is
sound because both ends are threads of the same process; the reader takes
ownership and frees it.

The reader resolves its `rpki_vrf` the same way `rpki_update_cb_sync_rtr()` does
(`rtr->tr_socket->ident_fp()` then `find_rpki_vrf_from_ident()`), and honours
`is_stopping()`.

If the shadow table is dropped, the message shrinks to `customer_asn` alone and
the provider array is never copied — 5.3 does not need it.

### 5.3 Revalidation (required)

ASPA changes are keyed by customer ASN, not by prefix, so
`revalidate_single_prefix()` does not apply: any route whose AS_PATH traverses
that ASN may change state.

After draining a batch of ASPA messages and updating the shadow table, arm a
single debounced per-VRF event (`t_aspa_revalidate`, 500 ms). The event walks
the VRF's RIBs for all `afi`/`safi` and calls the existing
`revalidate_bgp_node()`. Because the timer is only armed if not already
pending, the flood of records at initial cache sync collapses into one pass.

This makes the overflow handling that the ROA path needs unnecessary here — the
debounce already means "revalidate everything".

**Operational precondition.** `revalidate_bgp_node()` replays `dest->adj_in`,
and `bgp_update()` only populates `adj_in` when `bgp_adj_in_needed()` is true —
that is, when the peer has `soft-reconfiguration inbound` enabled or is under
BMP pre-policy monitoring (`bgpd/bgp_route.c:6092`). Without it, an ASPA table
change will not re-evaluate already-received routes, exactly as is already the
case for ROA updates. The documentation in section 9 must say so.

## 6. Validation entry point

In `bgp_rpki.h`, alongside `enum rpki_states`:

```c
enum aspa_states {
	ASPA_NOT_BEING_USED,
	ASPA_VALID,
	ASPA_INVALID,
	ASPA_UNKNOWN,
};
```

In `bgp_rpki.c`:

```c
static enum aspa_states rpki_aspa_validate_path(struct peer *peer,
						struct attr *attr,
						enum rtr_aspa_direction dir);
```

Behaviour:

1. Resolve `rpki_vrf` from `peer->bgp` exactly as `rpki_validate_prefix()` does;
   return `ASPA_NOT_BEING_USED` if absent or not synchronised.
2. Flatten `attr->aspath` into a `uint32_t[]`:
   - `AS_SEQUENCE` segments contribute their ASNs in order. Index 0 ends up
     being the leftmost (neighbor-side) ASN and index N-1 the origin, which is
     the order rtrlib wants (2.1).
   - `AS_CONFED_SEQUENCE` and `AS_CONFED_SET` segments are skipped; they are
     confederation-internal and not part of the externally visible path.
   - An `AS_SET` anywhere yields `ASPA_UNKNOWN`. The path is not a verifiable
     sequence of hops, and guessing is worse than declining.
   - No prepend de-duplication; rtrlib handles it (2.1).
   - Empty result, or no `aspath` at all (iBGP-originated), yields
     `ASPA_UNKNOWN`.
3. Call `rtr_mgr_aspa_validate()`. Map `RTR_ASPA_AS_PATH_VALID` / `_INVALID` /
   `_UNKNOWN` onto `ASPA_VALID` / `ASPA_INVALID` / `ASPA_UNKNOWN`; a non-success
   return from the function itself yields `ASPA_NOT_BEING_USED`.
4. Emit an `RPKI_DEBUG()` line with the direction and result, matching the style
   of the existing origin-validation debug output.

Buffer: size from `attr->aspath->count`, allocated with `MTYPE_BGP_RPKI_TEMP`
and freed before return.

## 7. Route-map integration

### 7.1 CLI

```
[no] match aspa <upstream|downstream> <valid|invalid|unknown>
```

`DEFUN_YANG match_aspa_cmd` / `no_match_aspa_cmd` in `bgp_rpki.c`, installed on
`RMAP_NODE` next to `match_rpki_cmd`.

### 7.2 yang

In `yang/frr-bgp-route-map.yang`:

```yang
identity aspa {
  base frr-route-map:rmap-match-type;
  description "Control ASPA AS_PATH verification settings";
}
```

and a `case aspa` with two leaves rather than one fused enum, so that `show run`
and NETCONF stay readable. Both are `mandatory true`, which guarantees that
whenever the `aspa` case exists both values are present:

```yang
case aspa {
  when "derived-from-or-self(../frr-route-map:condition, 'frr-bgp-route-map:aspa')";
  leaf aspa-direction {
    type enumeration { enum "upstream" { value 0; } enum "downstream" { value 1; } }
    mandatory true;
  }
  leaf aspa-state {
    type enumeration {
      enum "invalid" { value 0; }
      enum "unknown" { value 1; }
      enum "valid"   { value 2; }
    }
    mandatory true;
  }
}
```

### 7.3 Northbound

`bgpd/bgp_routemap_nb.h` / `_nb.c` / `_nb_config.c` gain
`lib_route_map_entry_match_condition_rmap_match_condition_aspa_direction_{modify,destroy}`
and `..._aspa_state_{modify,destroy}`, following the existing `rpki` pair.

The route-map layer takes a single string argument per rule, but the model has
two leaves that arrive as two separate northbound changes. Rather than have each
callback install half a rule, both `modify` callbacks delegate to one helper:

```c
static int bgp_route_match_aspa_install(struct nb_cb_modify_args *args);
```

The helper reads *both* leaves off the shared parent node
(`yang_dnode_get_string(args->dnode, "../aspa-direction")` and
`"../aspa-state"`), composes the argument `"<direction> <state>"`, and calls
`bgp_route_match_add()` with rule name `"aspa"`. It must be idempotent, since
it runs once per leaf: on the second invocation it replaces the rule installed
by the first. The `mandatory true` constraints in 7.2 mean both leaves are
readable by the time `NB_EV_APPLY` runs.

Either `destroy` callback removes the whole `"aspa"` rule.

`route_match_aspa_compile()` parses the two halves back out into

```c
struct rmap_aspa { enum rtr_aspa_direction direction; enum aspa_states state; };
```

so `route_match_aspa()` performs exactly one validation.

### 7.4 Match handler

```c
static const struct route_map_rule_cmd route_match_aspa_cmd = {
	"aspa", route_match_aspa, route_match_aspa_compile, route_match_aspa_free };
```

`route_match_aspa()` calls `rpki_aspa_validate_path(path->peer, path->attr,
rule->direction)` and returns `RMAP_MATCH` when it equals `rule->state`.

## 8. Show output

### 8.1 `show rpki aspa [ASNUM] [json]`

Installed at `VIEW_NODE`, with the same VRF variants the other `show rpki`
commands have. Dumps the shadow table from 5.1, sorted by customer ASN, with
provider ASNs rendered in the VRF's configured AS notation
(`bgp_get_asnotation()`), consistent with `print_record()`.

Text form:

```
Customer ASN   Provider ASNs
64500          64496, 64497
64501          64496
```

### 8.2 Per-route state

Added to the per-prefix detail path only (`route_vty_out_detail()` in
`bgp_route.c`), reporting **both** directions, since outside a route-map there
is no direction to pick:

```json
{ "aspaUpstream": "invalid", "aspaDownstream": "valid" }
```

Deliberately **not** added to `route_vty_short_status_out()`. That function runs
once per line in full-table dumps, and two AS_PATH walks per path — each taking
rtrlib's table read lock per hop — would make `show bgp` materially slower for
every user whether or not they use ASPA.

Exposed through a new hook declared in `bgpd.h` and defined in `bgp_route.c`,
mirroring `bgp_rpki_prefix_status`, so `bgp_route.c` keeps no build dependency
on the rpki module. Unlike the RPKI hook it carries a direction, and it takes no
prefix, because ASPA validates the AS_PATH rather than the origin:

```c
DECLARE_HOOK(bgp_aspa_path_status,
	     (struct peer *peer, struct attr *attr, int direction),
	     (peer, attr, direction));
```

`direction` is an `int` rather than `enum rtr_aspa_direction` so that `bgpd.h`
stays free of rtrlib types; the rpki module casts it. `bgp_route.c` calls the
hook twice, once per direction, and omits the fields entirely when the result
is `ASPA_NOT_BEING_USED` (which is also what an unloaded module yields).

### 8.3 Debug

`debug rpki` covers ASPA validation results and shadow-table updates, using the
existing `RPKI_DEBUG()` macro.

## 9. Documentation

`doc/user/rpki.rst` gains an ASPA section covering:

- the rtrlib requirement, and that it is a build-time capability
  (`FOUND_ASPA`) not a runtime one;
- `match aspa`, with worked examples for a customer session and a transit
  session;
- `show rpki aspa`;
- an explicit note on why the direction is stated in the route-map rather than
  derived from `neighbor X local-role`, and that the two are independent;
- that `soft-reconfiguration inbound` is required on a peer for ASPA table
  changes to re-evaluate its already-received routes (5.3).

## 10. Testing

- **Build matrix.** The port must be compiled both ways: against rtrlib master
  (ASPA on) and against rtrlib v0.8.0 (ASPA off, compat header active). Both
  configurations are the acceptance criterion for the rename in section 4.
- **Topotest** `tests/topotests/bgp_aspa_topo1/`, modelled on
  `bgp_rpki_topo1`, with a StayRTR instance serving an ASPA-bearing JSON over
  RTR version 2. Cases: upstream valid, upstream invalid, downstream valid for
  the same path that is upstream invalid (the asymmetry in 3.1), and unknown
  for an ASN with no attestation.

### 10.1 Known verification gaps

- **SSH transport paths: gap closed.** Originally these were ported blind,
  because libssh headers were absent and `FOUND_SSH` came back negative,
  leaving every `#if defined(FOUND_SSH)` block outside the preprocessor's
  reach. `libssh-dev` has since been installed and rtrlib master rebuilt with
  `RTRLIB_TRANSPORT_SSH=On`, so FRR now configures with `FOUND_SSH=1` and the
  SSH blocks compile. They build with no warnings and the module links
  `rtr_tr_ssh_init`, confirming the `tr_ssh_config` -> `rtr_tr_ssh_config` and
  `tr_ssh_init` -> `rtr_tr_ssh_init` renames.

  Note that the `'host' may be used uninitialized` warnings seen in
  `rpki_create_socket()` appear *only* in non-SSH builds: without `FOUND_SSH`
  the `else` branch that assigns them is preprocessed away. They are
  pre-existing and unrelated to this work.
- **Topotest execution** depends on the available StayRTR supporting RTR
  version 2 and ASPA PDUs. To be confirmed before the test is claimed to pass.

## 10.2 Deferred follow-ups

- **Report the rtrlib ASPA leak upstream** (see 2.7). Deliberately deferred
  until the FRR implementation is finished; not a blocker, since bgpd already
  frees the array itself. The report should cover both the undocumented
  ownership transfer in `aspa_table_notify_clients()` and the early-return
  leak in rtrlib's own `rtrclient`.

## 11. Out of scope

- Any built-in accept/reject/depref policy (`bgp aspa policy ...`).
- Deriving direction from `neighbor X local-role` (see 3.1).
- Locally configured ASPA sets analogous to OpenBGPD's `aspa-set`; ASPA data
  comes only from RTR caches.
- Propagating ASPA state to iBGP peers via an extended community, as
  `PEER_FLAG_SEND_EXT_COMMUNITY_RPKI` does for origin validation. No such
  community is standardised for ASPA.
- BGPsec / router key support, which rtrlib's `spki_table` also offers.

## 12. Implementation order

1. Port `bgp_rpki.c` to the new rtrlib names; add `bgp_rpki_compat.h` and the
   `configure.ac` probe. Verify both builds. No behaviour change.
2. Add `rtr_mgr_add_aspa_support()` and the init reordering from 4.2.
3. Add `enum aspa_states` and `rpki_aspa_validate_path()`.
4. Add the route-map match: yang, northbound, CLI, handler.
5. Add the per-route detail output and the `bgp_aspa_path_status` hook (8.2).
6. Add the sync socketpair and debounced revalidation (5.2, 5.3), plus the
   shadow table (5.1).
7. Add `show rpki aspa` (8.1).
8. Documentation and topotest.

Steps 1 and 2 are a prerequisite for everything else.

The shadow table (5.1) and step 7 stand or fall together — the table exists
only to feed `show rpki aspa` — and both can be dropped from a first cut
without affecting anything else. Step 5 does *not* depend on them; it reads
rtrlib's table directly.

Within step 6, only the shadow table (5.1) is optional. The socketpair (5.2)
and the debounced revalidation (5.3) are required regardless: they are the only
thing that re-evaluates routes when the ASPA set changes. Without them, ASPA
state would be correct at the moment a route is received but go stale until the
next update for that prefix.
