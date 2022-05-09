/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAJOR_FROM_VERSION(V) (((V) >> 16) & 0xffu)
#define MINOR_FROM_VERSION(V) ((V) & 0xffu)

/*
 * A file version node.
 */
#define CT_FILEVERSION  (1u << 0u)
/*
 * key=value with unsigned long value.
 */
#define CT_INTVAL       (1u << 1u)
/*
 * key=value with string value.
 */
#define CT_STRINGVAL    (1u << 2u)
/*
 * key=value with version value (packed as a 16/16 bit unsigned integer).
 */
#define CT_VERSIONVAL   (1u << 3u)
/*
 * key=value with bare string value.
 */
#define CT_BAREVAL      (1u << 4u)
/*
 * Structure value.
 */
#define CT_STRUCT       (1u << 5u)
/*
 * Indexed structure value.
 */
#define CT_IDX_STRUCT   (1u << 6u)
/*
 * Bare list.  List contains bare values.
 */
#define CT_BARELIST     (1u << 7u)
/*
 * End-of-line comment.
 */
#define CT_EOC          (1u << 8u)
/* 
 * A bare value.
 */
#define CT_BARE         (1u << 9u)
/*
 * A bare constant, i.e., a bare word outside of a list that
 * represents its own configuration element.
 */
#define CT_BARECONST    (1u << 10u)

/*
 * Mask for all types that have a key.  This excludes FILEVERSION,
 * EOC, and BARE which reuse the key field for the value.
 */
#define CT_HAS_KEY_MASK (CT_INTVAL | CT_STRINGVAL | CT_VERSIONVAL |  \
			 CT_BAREVAL | CT_STRINGVAL | CT_IDX_STRUCT | \
			 CT_BARELIST | CT_BARECONST)

/***** Node Types *****/
struct ConfigBaseNode;

struct ConfigBaseNode {
    struct ConfigBaseNode *next, *prev;
    unsigned int type;
    char *key;
    uint16_t line;
    uint16_t flags;
};

struct ConfigFileVersionNode {
    struct ConfigBaseNode base;
};

struct ConfigIntValNode {
    struct ConfigBaseNode base;
    unsigned long value;
};

struct ConfigStringValNode {
    struct ConfigBaseNode base;
    char *value;
};

struct ConfigVersionValNode {
    struct ConfigBaseNode base;
    unsigned int value;
};

struct ConfigBareValNode {
    struct ConfigBaseNode base;
    char *value;
};

struct ConfigIdxStructNode {
    struct ConfigBaseNode base;
    unsigned long idx;
    struct ConfigBaseNode *beforeOpen;
    struct ConfigBaseNode *value;
};

struct ConfigStructNode {
    struct ConfigBaseNode base;
    struct ConfigBaseNode *beforeOpen;
    struct ConfigBaseNode *value;
};

struct ConfigBareNode {
    /* Reuses base.key for bare value. */
    struct ConfigBaseNode base;
};

struct ConfigBareListNode {
    struct ConfigBaseNode base;
    struct ConfigBaseNode *beforeOpen;
    /* either a ConfigBareNode or a ConfigEOCNode */
    struct ConfigBaseNode *value;
};

struct ConfigEOCNode {
    /* Reuses base.key for comment */
    struct ConfigBaseNode base;
};

struct ConfigBareConstNode {
    struct ConfigBaseNode base;
};

/* Casting from base type functions */
static inline struct ConfigFileVersionNode *
confignode_to_fileversion(struct ConfigBaseNode *n)
{
    return (struct ConfigFileVersionNode *)
        (((char *)n) - offsetof(struct ConfigFileVersionNode, base));
}

static inline struct ConfigIntValNode *
confignode_to_intval(struct ConfigBaseNode *n)
{
    return (struct ConfigIntValNode *)
        (((char *)n) - offsetof(struct ConfigIntValNode, base));
}

static inline struct ConfigStringValNode *
confignode_to_stringval(struct ConfigBaseNode *n)
{
    return (struct ConfigStringValNode *)
        (((char *)n) - offsetof(struct ConfigStringValNode, base));
}

static inline struct ConfigVersionValNode *
confignode_to_versionval(struct ConfigBaseNode *n)
{
    return (struct ConfigVersionValNode *)
        (((char *)n) - offsetof(struct ConfigVersionValNode, base));
}

static inline struct ConfigBareValNode *
confignode_to_bareval(struct ConfigBaseNode *n)
{
    return (struct ConfigBareValNode *)
        (((char *)n) - offsetof(struct ConfigBareValNode, base));
}

static inline struct ConfigIdxStructNode *
confignode_to_idxstruct(struct ConfigBaseNode *n)
{
    return (struct ConfigIdxStructNode *)
        (((char *)n) - offsetof(struct ConfigIdxStructNode, base));
}

static inline struct ConfigStructNode *
confignode_to_struct(struct ConfigBaseNode *n)
{
    return (struct ConfigStructNode *)
        (((char *)n) - offsetof(struct ConfigStructNode, base));
}

static inline struct ConfigBareNode *
confignode_to_bare(struct ConfigBaseNode *n)
{
    return (struct ConfigBareNode *)
        (((char *)n) - offsetof(struct ConfigBareNode, base));
}

static inline struct ConfigBareListNode *
confignode_to_barelist(struct ConfigBaseNode *n)
{
    return (struct ConfigBareListNode *)
        (((char *)n) - offsetof(struct ConfigBareListNode, base));
}

static inline struct ConfigEOCNode *
confignode_to_eoc(struct ConfigBaseNode *n)
{
    return (struct ConfigEOCNode *)
        (((char *)n) - offsetof(struct ConfigEOCNode, base));
}

static inline struct ConfigBareConstNode *
confignode_to_bareconst(struct ConfigBaseNode *n)
{
    return (struct ConfigBareConstNode *)
        (((char *)n) - offsetof(struct ConfigBareConstNode, base));
}

/* Freeing functions */

/**
 * Free a node and all its descendants.
 * @param n Node to free.
 */
void confignode_deepfree(struct ConfigBaseNode *n);

/**
 * Free only one node but not its descendants.
 * This function basically is a dispatcher based on the node type.
 * @param n Node to free.
 */
void confignode_free(struct ConfigBaseNode *n);

static inline void confignode_freefileversion(struct ConfigFileVersionNode *n)
{
    if (n) {
        free(n->base.key);
        free(n);
    }
}

static inline void confignode_freeintval(struct ConfigIntValNode *n)
{
    if (n) {
        free(n->base.key);
        free(n);
    }
}

static inline void confignode_freestringval(struct ConfigStringValNode *n)
{
    if (n) {
        free(n->base.key);
        free(n->value);
        free(n);
    }
}

static inline void confignode_freeversionval(struct ConfigVersionValNode *n)
{
    if (n) {
        free(n->base.key);
        free(n);
    }
}

static inline void confignode_freebareval(struct ConfigBareValNode *n)
{
    if (n) {
        free(n->base.key);
        free(n->value);
        free(n);
    }
}

static inline void confignode_freeidxstruct(struct ConfigIdxStructNode *n)
{
    if (n) {
        free(n->base.key);
        confignode_deepfree(n->beforeOpen);
        confignode_deepfree(n->value);
        free(n);
    }
}

static inline void confignode_freestruct(struct ConfigStructNode *n)
{
    if (n) {
        free(n->base.key);
        confignode_deepfree(n->beforeOpen);
        confignode_deepfree(n->value);
        free(n);
    }
}

static inline void confignode_freebare(struct ConfigBareNode *n)
{
    if (n) {
        free(n->base.key);
        free(n);
    }
}

static inline void confignode_freebarelist(struct ConfigBareListNode *n)
{
    if (n) {
        free(n->base.key);
        confignode_deepfree(n->beforeOpen);
        confignode_deepfree(n->value);
        free(n);
    }
}

static inline void confignode_freeeoc(struct ConfigEOCNode *n)
{
    if (n) {
        free(n->base.key);
        free(n);
    }
}

static inline void confignode_freebareconst(struct ConfigBareConstNode *n)
{
    if (n) {
        free(n->base.key);
        free(n);
    }
}

/* Allocation functions */

static inline struct ConfigFileVersionNode *
confignode_allocfileversion(char *version, int line)
{
    struct ConfigFileVersionNode *res =
        malloc(sizeof(struct ConfigFileVersionNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = version;
        res->base.type = CT_FILEVERSION;
        res->base.line = line;
    }
    return res;
}

static inline struct ConfigIntValNode *
confignode_allocintval(char *key, unsigned long val, int line)
{
    struct ConfigIntValNode *res = malloc(sizeof(struct ConfigIntValNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = key;
        res->base.type = CT_INTVAL;
        res->base.line = line;
        res->base.flags = 0;
        res->value = val;
    }
    return res;
}

static inline struct ConfigVersionValNode *
confignode_allocversionval(char *key, unsigned long val, int line)
{
    struct ConfigVersionValNode *res = malloc(sizeof(struct ConfigVersionValNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = key;
        res->base.type = CT_VERSIONVAL;
        res->base.line = line;
        res->base.flags = 0;
        res->value = val;
    }
    return res;
}

static inline struct ConfigStringValNode *
confignode_allocstringval(char *key, char *val, int line)
{
    struct ConfigStringValNode *res = malloc(sizeof(struct ConfigStringValNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = key;
        res->base.type = CT_STRINGVAL;
        res->base.line = line;
        res->base.flags = 0;
        res->value = val;
    }
    return res;
}

static inline struct ConfigBareValNode *
confignode_allocbareval(char *key, char *val, int line)
{
    struct ConfigBareValNode *res = malloc(sizeof(struct ConfigBareValNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = key;
        res->base.type = CT_BAREVAL;
        res->base.line = line;
        res->base.flags = 0;
        res->value = val;
    }
    return res;
}

static inline struct ConfigIdxStructNode *
confignode_allocidxstruct(char *key, unsigned long num,
                          struct ConfigBaseNode *beforeOpen,
                          struct ConfigBaseNode *value,
                          int line)
{
    struct ConfigIdxStructNode *res =
        malloc(sizeof(struct ConfigIdxStructNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = key;
        res->base.type = CT_IDX_STRUCT;
        res->base.line = line;
        res->base.flags = 0;
        res->idx = num;
        res->beforeOpen = beforeOpen;
        res->value = value;
    }
    return res;
}

static inline struct ConfigStructNode *
confignode_allocstruct(char *key,
                       struct ConfigBaseNode *beforeOpen,
                       struct ConfigBaseNode *value,
                       int line)
{
    struct ConfigStructNode *res = malloc(sizeof(struct ConfigStructNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = key;
        res->base.type = CT_STRUCT;
        res->beforeOpen = beforeOpen;
        res->base.line = line;
        res->base.flags = 0;
        res->value = value;
    }
    return res;
}

static inline struct ConfigBareListNode *
confignode_allocbarelist(char *key,
                         struct ConfigBaseNode *beforeOpen,
                         struct ConfigBaseNode *value,
                         int line)
{
    struct ConfigBareListNode *res = malloc(sizeof(struct ConfigBareListNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = key;
        res->base.type = CT_BARELIST;
        res->base.line = line;
        res->base.flags = 0;
        res->beforeOpen = beforeOpen;
        res->value = value;
    }
    return res;
}

static inline struct ConfigBareNode *confignode_allocbare(char *bareval,
                                                          int line)
{
    struct ConfigBareNode *res = malloc(sizeof(struct ConfigBareNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = bareval;
        res->base.type = CT_BARE;
        res->base.line = line;
        res->base.flags = 0;
    }
    return res;
}

static inline struct ConfigEOCNode *confignode_alloceoc(char *comment, int line)
{
    struct ConfigEOCNode *res = malloc(sizeof(struct ConfigEOCNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = comment;
        res->base.type = CT_EOC;
        res->base.line = line;
        res->base.flags = 0;
    }
    return res;
}

static inline struct ConfigBareConstNode *confignode_allocbareconst(char *key,
                                                                    int line)
{
    struct ConfigBareConstNode *res = malloc(sizeof(struct ConfigBareConstNode));

    if (res) {
        res->base.next = res->base.prev = &(res->base);
        res->base.key = key;
        res->base.type = CT_BARECONST;
        res->base.line = line;
        res->base.flags = 0;
    }
    return res;
}

/* Convenience functions for AST manipulation.  These functions
   automatically append an EOC-node to the correct node which
   optionally includes a comment.  If no comment is desired, simply
   pass NULL for the comment argument. The dumpable versions below
   also strdup all strings (keys, values, and the optional
   comment). */
struct ConfigFileVersionNode *
confignode_allocfileversiondumpable(char *version, int line, char *comment);

struct ConfigIntValNode *
confignode_allocintvaldumpable(char *key, unsigned long val, int line,
                               char *comment);

struct ConfigVersionValNode *
confignode_allocversionvaldumpable(char *key, unsigned long val, int line,
                                   char *comment);

struct ConfigStringValNode *
confignode_allocstringvaldumpable(char *key, char *val, int line, char *comment);

struct ConfigBareValNode *
confignode_allocbarevaldumpable(char *key, char *val, int line, char *comment);

struct ConfigIdxStructNode *
confignode_allocidxstructdumpable(char *key, unsigned long num,
                                  struct ConfigBaseNode *beforeOpen,
                                  struct ConfigBaseNode *value,
                                  int line, char *comment);

struct ConfigStructNode *
confignode_allocstructdumpable(char *key,
                               struct ConfigBaseNode *beforeOpen,
                               struct ConfigBaseNode *value,
                               int line, char *comment);

struct ConfigBareListNode *
confignode_allocbarelistdumpable(char *key,
                                 struct ConfigBaseNode *beforeOpen,
                                 struct ConfigBaseNode *value,
                                 int line, char *comment);

struct ConfigBareNode *
confignode_allocbaredumpable(char *bareval, int line, char *comment);

struct ConfigBareConstNode *
confignode_allocbareconstdumpable(char *key, int line, char *comment);

/* Append the list n2 to the end of the list n1.
   NULL is considered as empty list. */
static inline struct ConfigBaseNode *confignode_append(struct ConfigBaseNode *n1,
                                                       struct ConfigBaseNode *n2)
{
    struct ConfigBaseNode *tmp;

    if (n1) {
        if (n2) {
            n1->prev->next = n2;
            tmp = n2->prev;
            n2->prev = n1->prev;
            tmp->next = n1;
            n1->prev = tmp;
            return n1;
        } else {
            return n1;
        }
    } else {
        return n2;
    }
}

/* Dumping support */

#define CONFIG_FLAG_INT_PRINT_MODE_HEX (1 << 0u)

struct ConfigDumpCb {
    /* Called for every node to update the dump flags. */
    unsigned (*flags)(struct ConfigBaseNode *n, unsigned curflags);
};

void confignode_dump(FILE *fp, struct ConfigBaseNode *n,
                     struct ConfigDumpCb *cb, unsigned indent);

/* Iteration and searching */

/*
 * Iterate over a configuration.
 * i is the iterator of type struct ConfigBaseNode *
 * c is the configuration to iterate over (of type struct ConfigBaseNode *)
 * f is an integer
 */
#define confignode_foreach(i,c,f) \
    for((i)=(c),(f)=1;(f)||(i)!=(c);(i)=(i)->next,(f)=0)

static inline struct ConfigBaseNode *
confignode_find(struct ConfigBaseNode *cfg, const char *key)
{
    struct ConfigBaseNode *i;

    if (cfg) {
        i = cfg;
        do {
            if ((i->type & CT_HAS_KEY_MASK) && strcmp(key, i->key) == 0)
                return i;
            i = i->next;
        } while (i != cfg);
    }
    return NULL;
}

static inline struct ConfigIdxStructNode *
confignode_findidx(struct ConfigBaseNode *cfg, const char *key, unsigned idx)
{
    struct ConfigBaseNode *i;
    struct ConfigIdxStructNode *res;

    if (cfg) {
        i = cfg;
        do {
            if ((i->type & CT_IDX_STRUCT) && strcmp(key, i->key) == 0) {
                res = confignode_to_idxstruct(i);
                if (res->idx == idx)
                    return res;
            }
            i = i->next;
        } while (i != cfg);
    }
    return NULL;
}

/* Type checking */

static inline int confignode_hastype(struct ConfigBaseNode *n,
                                     unsigned typemask)
{
    return (n->type & typemask) != 0;
}

/* Convenience functions */

static inline char *confignode_getstr(struct ConfigBaseNode *n)
{
    if (n->type & CT_STRINGVAL)
        return confignode_to_stringval(n)->value;
    if (n->type & CT_BAREVAL)
        return confignode_to_bareval(n)->value;
    return NULL;
}

/* Returns 0 if a valid version was found and -1 otherwise. */
static inline int confignode_getversion(struct ConfigBaseNode *n,
                                        unsigned int *version)
{
    int res = 0;
    unsigned int major, minor;

    if (n->type & CT_VERSIONVAL) {
        *version = confignode_to_versionval(n)->value;
    } else if (n->type & CT_STRINGVAL) {
        if (sscanf(confignode_to_stringval(n)->value, "%u.%u",
                    &major, &minor) == 2)
            *version = major << 16 | minor;
        else
            res = -1;
    } else {
        res = -1;
    }
    return res;
}

#endif
