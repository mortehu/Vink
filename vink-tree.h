#ifndef VINK_TREE_H_
#define VINK_TREE_H_ 1

struct vink_tree;

struct vink_tree*
vink_tree_create (const char* name);

void
vink_tree_destroy (struct vink_tree* t);

void
vink_tree_create_node (struct vink_tree* t, const char* path,
                       const char* value);

long long int
vink_tree_get_integer (const struct vink_tree* t, const char* path);

int
vink_tree_get_bool (const struct vink_tree* t, const char* path);

const char*
vink_tree_get_string (const struct vink_tree* t, const char* path);

long long int
vink_tree_get_integer_default (const struct vink_tree* t, const char* path,
                               long long int def);

int
vink_tree_get_bool_default (const struct vink_tree* t, const char* path,
                            int def);

const char*
vink_tree_get_string_default (const struct vink_tree* t, const char* path,
                              const char* def);

size_t
vink_tree_get_strings (const struct vink_tree* t, const char* path,
                       char*** result);

struct vink_tree*
vink_tree_load_cfg (const char* path);

#endif /* !VINK_TREE_H_ */
