/*
 * sockproxy_pd_trie.c - Compressed radix trie for cache-aware prefill EP selection
 *
 * SPDX-License-Identifier: (GPL-2.0)
 *
 * This is a self-contained module. It does NOT include sockproxy.h.
 * NOT thread-safe: callers must manage locking externally.
 * Lock ordering: pd_session_lock BEFORE pd_trie_lock -- caller manages all locking.
 *
 * The trie stores (text -> ep_idx) mappings where ep_idx is recorded at EVERY
 * node along the path (not just leaves). pd_trie_match() returns the deepest
 * node with a valid ep_idx (longest prefix match).
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* ---- Internal node structures (opaque to callers) ---- */

typedef struct pd_trie_child {
    unsigned char        key;      /* first byte of edge label */
    struct pd_trie_node *node;
    struct pd_trie_child *next;    /* linked list for children */
} pd_trie_child_t;

typedef struct pd_trie_node {
    char                *label;       /* compressed edge label (heap-allocated) */
    size_t               label_len;
    pd_trie_child_t     *children;    /* linked list of children */
    struct pd_trie_node *parent;      /* back-pointer for removal/merge */
    unsigned char        parent_key;  /* key under which parent stores this node */
    int                  ep_idx;      /* -1 = no EP assigned, >=0 = EP with affinity */
    uint64_t             access_ts;   /* last access timestamp (set via time(NULL)) */
} pd_trie_node_t;

struct pd_trie {
    pd_trie_node_t *root;       /* root node (label="" empty, ep_idx=-1) */
    size_t          node_count; /* total node count for eviction cap */
};

/* Forward declaration for the public type (matches sockproxy.h) */
typedef struct pd_trie pd_trie_t;

/* ---- Static helper functions ---- */

static size_t shared_prefix_len(const char *a, size_t a_len,
                                const char *b, size_t b_len)
{
    size_t min_len = a_len < b_len ? a_len : b_len;
    size_t i;
    for (i = 0; i < min_len; i++) {
        if (a[i] != b[i])
            break;
    }
    return i;
}

static pd_trie_child_t *find_child(pd_trie_node_t *node, unsigned char key)
{
    pd_trie_child_t *c = node->children;
    while (c) {
        if (c->key == key)
            return c;
        c = c->next;
    }
    return NULL;
}

static pd_trie_node_t *alloc_node(const char *label, size_t label_len)
{
    pd_trie_node_t *n = calloc(1, sizeof(*n));
    if (!n)
        return NULL;
    if (label_len > 0) {
        n->label = malloc(label_len + 1);
        if (!n->label) {
            free(n);
            return NULL;
        }
        memcpy(n->label, label, label_len);
        n->label[label_len] = '\0';
    } else {
        n->label = calloc(1, 1); /* empty string */
        if (!n->label) {
            free(n);
            return NULL;
        }
    }
    n->label_len = label_len;
    n->ep_idx = -1;
    n->children = NULL;
    n->parent = NULL;
    n->parent_key = 0;
    n->access_ts = 0;
    return n;
}

static void add_child(pd_trie_node_t *parent, unsigned char key,
                       pd_trie_node_t *child)
{
    pd_trie_child_t *entry = malloc(sizeof(*entry));
    if (!entry)
        return;
    entry->key = key;
    entry->node = child;
    entry->next = parent->children;
    parent->children = entry;

    child->parent = parent;
    child->parent_key = key;
}

static void remove_child(pd_trie_node_t *parent, unsigned char key)
{
    pd_trie_child_t **pp = &parent->children;
    while (*pp) {
        if ((*pp)->key == key) {
            pd_trie_child_t *victim = *pp;
            *pp = victim->next;
            free(victim);
            return;
        }
        pp = &(*pp)->next;
    }
}

static int count_children(pd_trie_node_t *node)
{
    int count = 0;
    pd_trie_child_t *c = node->children;
    while (c) {
        count++;
        c = c->next;
    }
    return count;
}

/*
 * merge_with_single_child: if node has exactly 1 child AND ep_idx==-1,
 * concatenate labels, replace node in grandparent's children, free node.
 * This prevents trie bloat after removal.
 */
static void merge_with_single_child(pd_trie_t *t, pd_trie_node_t *node)
{
    if (!node || node == t->root)
        return;
    if (count_children(node) != 1 || node->ep_idx >= 0)
        return;

    pd_trie_child_t *only_child_entry = node->children;
    pd_trie_node_t *child = only_child_entry->node;

    /* Concatenate labels: node->label + child->label */
    size_t new_len = node->label_len + child->label_len;
    char *new_label = malloc(new_len + 1);
    if (!new_label)
        return;
    memcpy(new_label, node->label, node->label_len);
    memcpy(new_label + node->label_len, child->label, child->label_len);
    new_label[new_len] = '\0';

    /* Update child's label */
    free(child->label);
    child->label = new_label;
    child->label_len = new_len;

    /* Replace node with child in grandparent's children list */
    pd_trie_node_t *grandparent = node->parent;
    if (grandparent) {
        /* Update child's parent_key to node's parent_key */
        child->parent_key = node->parent_key;
        child->parent = grandparent;

        /* Find the child entry in grandparent pointing to node, redirect to child */
        pd_trie_child_t *gc = grandparent->children;
        while (gc) {
            if (gc->node == node) {
                gc->node = child;
                gc->key = child->parent_key;
                break;
            }
            gc = gc->next;
        }
    }

    /* Free the merged node (only its own resources, child entries freed) */
    free(only_child_entry); /* the single child entry */
    node->children = NULL;  /* prevent double-free */
    free(node->label);
    free(node);

    t->node_count--;
}

/* Recursively free entire subtree */
static void free_subtree(pd_trie_t *t, pd_trie_node_t *node)
{
    if (!node)
        return;

    pd_trie_child_t *c = node->children;
    while (c) {
        pd_trie_child_t *next = c->next;
        free_subtree(t, c->node);
        free(c);
        c = next;
    }
    node->children = NULL;
    free(node->label);
    free(node);
    t->node_count--;
}

/* DFS helper: remove all nodes with matching ep_idx.
 *
 * Two-pass approach to avoid use-after-free:
 *  1. Clear ep_idx on matching nodes and collect childless non-root nodes to prune.
 *  2. Prune collected nodes and merge parents outside the DFS traversal.
 */

#define MAX_PRUNE_BATCH 256

static void remove_ep_clear_dfs(pd_trie_node_t *node, int ep_idx,
                                 pd_trie_node_t **prune_list, int *prune_count)
{
    if (!node)
        return;

    pd_trie_child_t *c = node->children;
    while (c) {
        pd_trie_child_t *next = c->next;
        remove_ep_clear_dfs(c->node, ep_idx, prune_list, prune_count);
        c = next;
    }

    if (node->ep_idx == ep_idx) {
        node->ep_idx = -1;
        /* Mark childless non-root nodes for pruning */
        if (!node->children && *prune_count < MAX_PRUNE_BATCH) {
            prune_list[(*prune_count)++] = node;
        }
    }
}

static void remove_ep_dfs(pd_trie_t *t, pd_trie_node_t *node, int ep_idx)
{
    if (!node)
        return;

    pd_trie_node_t *prune_list[MAX_PRUNE_BATCH];
    int prune_count = 0;

    /* Pass 1: Clear ep_idx and collect nodes to prune */
    remove_ep_clear_dfs(node, ep_idx, prune_list, &prune_count);

    /* Pass 2: Prune collected nodes (all are childless, ep_idx already -1) */
    for (int i = 0; i < prune_count; i++) {
        pd_trie_node_t *victim = prune_list[i];

        /* Victim may have gained children from a previous merge -- recheck */
        if (victim->children || victim == t->root)
            continue;

        pd_trie_node_t *parent = victim->parent;
        if (parent) {
            remove_child(parent, victim->parent_key);
        }
        free(victim->label);
        free(victim);
        t->node_count--;

        /* Try merging parent with its single remaining child */
        if (parent && parent != t->root) {
            merge_with_single_child(t, parent);
        }
    }
}

/* DFS helper for eviction: find leaf (ep_idx >= 0) with oldest access_ts */
static void find_oldest_leaf(pd_trie_node_t *node, pd_trie_node_t **oldest,
                             uint64_t *oldest_ts)
{
    if (!node)
        return;

    /* Check if this is a "leaf" with valid ep_idx */
    if (node->ep_idx >= 0 && !node->children) {
        if (*oldest == NULL || node->access_ts < *oldest_ts) {
            *oldest = node;
            *oldest_ts = node->access_ts;
        }
    }

    pd_trie_child_t *c = node->children;
    while (c) {
        find_oldest_leaf(c->node, oldest, oldest_ts);
        c = c->next;
    }
}

/* ---- Public API ---- */

pd_trie_t *pd_trie_create(void)
{
    pd_trie_t *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->root = alloc_node("", 0);
    if (!t->root) {
        free(t);
        return NULL;
    }
    t->node_count = 1;
    return t;
}

void pd_trie_free(pd_trie_t *t)
{
    if (!t)
        return;
    free_subtree(t, t->root);
    free(t);
}

int pd_trie_match(pd_trie_t *t, const char *text, size_t len,
                   int *ep_idx_out, float *match_rate_out)
{
    if (!t || !t->root || len == 0)
        return -1;

    pd_trie_node_t *cur = t->root;
    size_t pos = 0;          /* position in text */
    int last_ep = -1;
    size_t last_ep_pos = 0;

    /* Root can have an ep_idx */
    if (cur->ep_idx >= 0) {
        last_ep = cur->ep_idx;
        last_ep_pos = 0;
    }

    while (pos < len) {
        pd_trie_child_t *child_entry = find_child(cur, (unsigned char)text[pos]);
        if (!child_entry)
            break;

        pd_trie_node_t *child = child_entry->node;
        size_t match = shared_prefix_len(child->label, child->label_len,
                                          text + pos, len - pos);

        if (match == 0)
            break;

        pos += match;

        /* If we matched the entire edge label, we reached this node */
        if (match == child->label_len) {
            cur = child;
            if (cur->ep_idx >= 0) {
                last_ep = cur->ep_idx;
                last_ep_pos = pos;
                cur->access_ts = (uint64_t)time(NULL);
            }
        } else {
            /* Partial match on edge label -- can't descend further */
            break;
        }
    }

    if (last_ep >= 0) {
        if (ep_idx_out)
            *ep_idx_out = last_ep;
        if (match_rate_out)
            *match_rate_out = (float)last_ep_pos / (float)len;
        return 0;
    }

    return -1;
}

void pd_trie_insert(pd_trie_t *t, const char *text, size_t len, int ep_idx)
{
    if (!t || !t->root || len == 0)
        return;

    pd_trie_node_t *cur = t->root;
    size_t pos = 0;

    while (pos < len) {
        pd_trie_child_t *child_entry = find_child(cur, (unsigned char)text[pos]);

        if (!child_entry) {
            /* No matching child -- create a new leaf for remaining text */
            pd_trie_node_t *leaf = alloc_node(text + pos, len - pos);
            if (!leaf)
                return;
            leaf->ep_idx = ep_idx;
            leaf->access_ts = (uint64_t)time(NULL);
            add_child(cur, (unsigned char)text[pos], leaf);
            t->node_count++;
            return;
        }

        pd_trie_node_t *child = child_entry->node;
        size_t match = shared_prefix_len(child->label, child->label_len,
                                          text + pos, len - pos);

        if (match == child->label_len) {
            /* Full match of edge label -- descend into child */
            pos += match;
            cur = child;
        } else {
            /* Partial match -- split this node.
             *
             * Before: cur -> [child: "abcdef"]
             * After:  cur -> [mid: "abc"] -> [old_child: "def"]
             *                              -> [new_leaf: remaining text suffix]
             * (if no remaining text, mid gets the ep_idx directly)
             */

            /* Create intermediate node with shared prefix */
            pd_trie_node_t *mid = alloc_node(child->label, match);
            if (!mid)
                return;

            /* Shorten old child's label to the suffix after the shared prefix */
            size_t suffix_len = child->label_len - match;
            char *new_child_label = malloc(suffix_len + 1);
            if (!new_child_label) {
                free(mid->label);
                free(mid);
                return;
            }
            memcpy(new_child_label, child->label + match, suffix_len);
            new_child_label[suffix_len] = '\0';

            /* Replace child in cur's children list with mid */
            child_entry->node = mid;
            child_entry->key = (unsigned char)text[pos]; /* same first byte */
            mid->parent = cur;
            mid->parent_key = (unsigned char)text[pos];

            /* Old child becomes child of mid */
            free(child->label);
            child->label = new_child_label;
            child->label_len = suffix_len;
            add_child(mid, (unsigned char)new_child_label[0], child);

            t->node_count++; /* mid is new */

            pos += match;
            if (pos < len) {
                /* Still have remaining text -- create new leaf */
                pd_trie_node_t *leaf = alloc_node(text + pos, len - pos);
                if (!leaf)
                    return;
                leaf->ep_idx = ep_idx;
                leaf->access_ts = (uint64_t)time(NULL);
                add_child(mid, (unsigned char)text[pos], leaf);
                t->node_count++;
                /* Inherit old child's EP affinity — mid represents the shared
                 * prefix which already has cache locality from the prior
                 * insertion.  Without this, requests matching this prefix fall
                 * through to Tier 2 until an exact-prefix entry is inserted. */
                if (mid->ep_idx < 0)
                    mid->ep_idx = child->ep_idx;
            } else {
                /* Exact split point -- mid IS the target node */
                mid->ep_idx = ep_idx;
                mid->access_ts = (uint64_t)time(NULL);
            }
            return;
        }
    }

    /* Reached a node that exactly matches the full text -- update ep_idx */
    cur->ep_idx = ep_idx;
    cur->access_ts = (uint64_t)time(NULL);
}

void pd_trie_remove_ep(pd_trie_t *t, int ep_idx)
{
    if (!t || !t->root)
        return;
    remove_ep_dfs(t, t->root, ep_idx);
}

size_t pd_trie_node_count(pd_trie_t *t)
{
    if (!t)
        return 0;
    return t->node_count;
}

void pd_trie_evict_lru(pd_trie_t *t, size_t max_nodes)
{
    if (!t || !t->root)
        return;

    while (t->node_count > max_nodes) {
        pd_trie_node_t *oldest = NULL;
        uint64_t oldest_ts = 0;

        find_oldest_leaf(t->root, &oldest, &oldest_ts);
        if (!oldest)
            break; /* no more evictable leaves */

        /* Remove oldest leaf */
        pd_trie_node_t *parent = oldest->parent;
        if (parent) {
            remove_child(parent, oldest->parent_key);
        }
        free(oldest->label);
        free(oldest);
        t->node_count--;

        /* Try merging parent with its single remaining child */
        if (parent && parent != t->root) {
            merge_with_single_child(t, parent);
        }
    }
}
