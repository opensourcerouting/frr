#include <zebra.h>

#include "zlog.h"
#include "jhash.h"

#include "yakshave.h"
/*
enum yang_pathitem_kind {
	YPI_KIND_LEAF = 1,
	YPI_KIND_LEAFLIST,
	YPI_KIND_CONTAINER,
	YPI_KIND_LIST,
};

struct yang_pathitem {
	const char *name;
	enum yang_pathitem_kind kind;
};
*/

/* ********************** */

static int yk_children_cmp(const struct yk_child *a, const struct yk_child *b)
{
	return strcmp(a->name, b->name);
}

static uint32_t yk_children_hash(const struct yk_child *a)
{
	return jhash(a->name, strlen(a->name), 0xd1044749);
}

DECLARE_HASH(yk_children, struct yk_child, item, yk_children_cmp,
	     yk_children_hash);

/* root node */

struct yk_children_head ykchildren_root[1] = { INIT_HASH(ykchildren_root[0]) };

static void yk_dispatch(struct yk_request *req)
{
	struct ykctx_root root_ctx = {};
	struct yk_child *child, ref;
	struct ykchild_root *rchild;
	struct yk_request_pathcomp *prevpos;

	req->pathpos = yk_request_path_first(req->path);

	if (!req->pathpos) {
		zlog_debug("local dispatch at root");
		return;
	}

	ref.name = req->pathpos->name;

	child = yk_children_find(ykchildren_root, &ref);
	if (!child) {
		zlog_err("cannot find child named %pSE", ref.name);
		return;
	}
	rchild = container_of(child, struct ykchild_root, setup);

	prevpos = req->pathpos;
	req->pathpos = yk_request_path_next(req->path, prevpos);

	rchild->dispatch(&root_ctx, req);

	req->pathpos = prevpos;
}

extern void yk_register_root(struct ykchild_root *child);
void yk_register_root(struct ykchild_root *child)
{
	yk_children_add(ykchildren_root, &child->setup);
}

/* end root node */

struct ykchild_cont_a {
	struct yk_child setup;

	void (*dispatch)(struct ykctx_root *ctx,
			 struct yk_request *req);
};

#include "../test.c"
int main(int argc, char **argv)
{
	zlog_aux_init("NONE: ", LOG_DEBUG);

	struct yk_request req = {
		.op = YK_OP_GET,
	};
	yk_request_path_init(req.path);

	struct yk_request_pathcomp pc = {
		.name = "yk-test:cont-a",
		.argcount = 0,
	};
	yk_request_path_add_tail(req.path, &pc);

	yk_dispatch(&req);
	return 0;
}
