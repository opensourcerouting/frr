#include "lib/typesafe.h"
#include "lib/memory.h"
#include "lib/thread.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"
#include "lib/table.h"
#include "lib/if.h"

DECLARE_MGROUP(L3A)

struct thread_master;
struct vty;

PREDECL_HEAP(l3a_route_heap)
PREDECL_DLIST(l3a_route_iflist)

struct l3a_route {
	struct prefix p;

	union g_addr gw;
	char *ifname;

	struct interface *ifp;
	struct nexthop nh;
	struct l3a_route_iflist_item iflist_itm;

	struct timeval lifetime;
	struct l3a_route_heap_item heap_itm;
};

struct l3a_if {
	struct interface *ifp;

	struct l3a_route_iflist_head routes;

	bool snoop;
	int snoop_fd;
	struct thread *snoop_thread;

	bool arp_snoop;
	int arp_fd;
	struct thread *arp_thread;
};

extern struct route_table *l3a_v6;

void l3a_route_update(union prefixconstptr pfx, int64_t lifetime,
		      const union g_addr *addr, const char *ifname,
		      uint64_t *tags, size_t n_tags);

void l3a_dhcpv6_snoop(struct l3a_if *l3a_if);
void l3a_arp_snoop(struct l3a_if *l3a_if);

void l3a_zebra_update(struct l3a_route *l3ar);
void l3a_zebra_remove(struct l3a_route *l3ar);

struct l3a_if *l3a_if_get_byname(const char *name);

void l3a_route_init(struct thread_master *tm);
void l3a_zebra_init(struct thread_master *tm);
void l3a_vty_init(void);

void l3a_dhcpv6_show(struct vty *vty);
void l3a_dhcpv6_db(const char *filename);

