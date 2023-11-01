#include "typesafe.h"

#include "json.h"

PREDECL_DLIST(yk_request_path);

struct yk_request_patharg {
	const char *name;
	const char *value;
};

struct yk_request_pathcomp {
	struct yk_request_path_item item;

	const char *name;
	size_t argcount;
	struct yk_request_patharg args[0];
};

DECLARE_DLIST(yk_request_path, struct yk_request_pathcomp, item);

enum yk_op {
	YK_OP_GET = 0,
};

struct yk_request {
	enum yk_op op;

	struct yk_request_path_head path[1];
	struct yk_request_pathcomp *pathpos;

	struct json_object *json;
};


PREDECL_HASH(yk_children);

struct yk_child {
	struct yk_children_item item;

	const char *name;
};

struct ykctx_root {
	int dummy;
};

struct ykchild_root {
	struct yk_child setup;

	void (*dispatch)(struct ykctx_root *ctx,
			 struct yk_request *req);
};


/* */

PREDECL_RBTREE_UNIQ(items);

struct item {
	struct items_item itm;
	uint32_t id;

	uint32_t opt1;
	uint32_t opt2;
	uint32_t opt3;
};

static inline int items_cmp(const struct item *a,
			    const struct item *b)
{
	return numcmp(a->id, b->id);
}

DECLARE_RBTREE_UNIQ(items, struct item, itm, items_cmp);

extern struct items_head items[1];
