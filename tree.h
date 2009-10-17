#ifndef TREE_H_
#define TREE_H_ 1

struct tree;

struct tree*
tree_create(const char* name);

void
tree_destroy(struct tree* t);

void
tree_create_node(struct tree* t, const char* path, const char* value);

long long int
tree_get_integer(const struct tree* t, const char* path);

const char*
tree_get_string(const struct tree* t, const char* path);

struct tree*
tree_load_cfg(const char* path);

#endif /* !TREE_H_ */
