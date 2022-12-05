#include "typesafe.h"

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


