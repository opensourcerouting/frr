#include <zebra.h>

#include "persist.h"
#include "memory.h"

static struct persist_targets_head tgts[1] = INIT_SORTLIST_NONUNIQ(tgts);

struct persist_targets_head *ps_backends(struct vrf *vrf)
{
	/* FIXME TODO */
	return tgts;
}

void ps_backend_add(struct vrf *vrf, struct persist_target *tgt)
{
	persist_targets_add(tgts, tgt);
}

void ps_backend_del(struct vrf *vrf, struct persist_target *tgt)
{
	persist_targets_del(tgts, tgt);
}
