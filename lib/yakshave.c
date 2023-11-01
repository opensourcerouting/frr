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

	req->json = NULL;
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
	if (req->op == YK_OP_GET) {
		struct json_object *json = json_object_new_object();
		json_object_object_add(json, child->name, req->json);
		req->json = json;
	}

	req->pathpos = prevpos;
}

extern void yk_register_root(struct ykchild_root *child);
void yk_register_root(struct ykchild_root *child)
{
	yk_children_add(ykchildren_root, &child->setup);
}

/* end root node */

#include "../test.c"

struct items_head items[1] = { INIT_RBTREE_UNIQ(items[0]), };

static struct item item23 = { .id = 23, .opt1 = 23, .opt2 = 2323, };
static struct item item42 = { .id = 42, .opt1 = 42, .opt2 = 4242, };

int main(int argc, char **argv)
{
	zlog_aux_init("NONE: ", LOG_DEBUG);

	items_add(items, &item23);
	items_add(items, &item42);

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

	const char *text = json_object_to_json_string_ext(req.json,
		JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
	printf("%s\n", text);
	json_object_free(req.json);

	return 0;
}
