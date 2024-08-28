#include "configuration.h"

void confignode_deepfree(struct ConfigBaseNode *n)
{
    struct ConfigBaseNode *b, *i, *t;

    if (n) {
        b = n;
        i = n->next;
        while (i != b) {
            t = i->next;
            confignode_free(i);
            i = t;
        }
        confignode_free(n);
    }
}

void confignode_free(struct ConfigBaseNode *n)
{
    if (n) {
        switch (n->type) {
        case CT_FILEVERSION:
            confignode_freefileversion(confignode_to_fileversion(n));
            break;
        case CT_INTVAL:
            confignode_freeintval(confignode_to_intval(n));
            break;
        case CT_STRINGVAL:
            confignode_freestringval(confignode_to_stringval(n));
            break;
        case CT_VERSIONVAL:
            confignode_freeversionval(confignode_to_versionval(n));
            break;
        case CT_BAREVAL:
            confignode_freebareval(confignode_to_bareval(n));
            break;
        case CT_STRUCT:
            confignode_freestruct(confignode_to_struct(n));
            break;
        case CT_IDX_STRUCT:
            confignode_freeidxstruct(confignode_to_idxstruct(n));
            break;
        case CT_BARELIST:
            confignode_freebarelist(confignode_to_barelist(n));
            break;
        case CT_EOC:
            confignode_freeeoc(confignode_to_eoc(n));
            break;
        case CT_BARE:
            confignode_freebare(confignode_to_bare(n));
            break;
        case CT_BARECONST:
            confignode_freebareconst(confignode_to_bareconst(n));
            break;
        case CT_NUMPAIR:
            confignode_freenumpair(confignode_to_numpair(n));
            break;
        case CT_NUMPAIRLIST:
            confignode_freenumpairlist(confignode_to_numpairlist(n));
            break;
        case CT_BARESTRINGCONST:
            confignode_freebarestringconst(confignode_to_barestringconst(n));
            break;
        default:
            break;
        }
    }
}

static void confignode_dump_indent(FILE *fp, unsigned indent)
{
    unsigned i;

    for (i = 0; i < indent; ++i)
        fputc(' ', fp);
}

static int confignode_dump_i(FILE *fp, struct ConfigBaseNode *n,
                             struct ConfigDumpCb *cb, unsigned flags,
                             unsigned indent, unsigned curindent,
                             unsigned numbares, int curatbol);

static void confignode_dumpstruct(FILE *fp, struct ConfigStructNode *n,
                                  struct ConfigDumpCb *cb,
                                  unsigned flags, unsigned indent,
                                  unsigned curindent)
{
    if (n->beforeOpen) {
        fputs(n->base.key, fp);
        if (confignode_dump_i(fp, n->beforeOpen, cb, flags, indent, curindent, 0, 0))
            confignode_dump_indent(fp, curindent);
        fputc('{', fp);
    } else {
        fprintf(fp, "%s {", n->base.key);
    }
    if (n->value)
        if (confignode_dump_i(fp, n->value, cb, flags, indent, curindent + indent, 0, 0))
            confignode_dump_indent(fp, curindent);
    fputc('}', fp);
}

static void confignode_dumpidxstruct(FILE *fp, struct ConfigIdxStructNode *n,
                                     struct ConfigDumpCb *cb,
                                     unsigned flags, unsigned indent,
                                     unsigned curindent)
{
    if (n->beforeOpen) {
        fprintf(fp, "%s %lu", n->base.key, n->idx);
        if (confignode_dump_i(fp, n->beforeOpen, cb, flags, indent, curindent, 0, 0))
            confignode_dump_indent(fp, curindent);
        fputc('{', fp);
    } else {
        fprintf(fp, "%s %lu {", n->base.key, n->idx);
    }
    if (n->value)
        if (confignode_dump_i(fp, n->value, cb, flags, indent, curindent + indent, 0, 0))
            confignode_dump_indent(fp, curindent);
    fputc('}', fp);
}

static void confignode_dumpbarelist(FILE *fp, struct ConfigBareListNode *n,
                                    struct ConfigDumpCb *cb,
                                    unsigned flags, unsigned indent,
                                    unsigned curindent)
{
    struct ConfigBaseNode *i;
    unsigned num = 0, braceindent = curindent, valindent = 2;
    int f;

    if (n->beforeOpen) {
        fputs(n->base.key, fp);
        if (confignode_dump_i(fp, n->beforeOpen, cb, flags, indent, curindent, 0, 0)) {
            confignode_dump_indent(fp, curindent);
            valindent = indent;
        } else {
            braceindent += strlen(n->base.key) + 1;
        }
        fputc('(', fp);
    } else {
        fprintf(fp, "%s (", n->base.key);
        braceindent += strlen(n->base.key) + 1;
    }
    if (n->value) {
        confignode_foreach(i, n->value, f)
            num += (unsigned) confignode_hastype(i, CT_BARE);
        if (confignode_dump_i(fp, n->value, cb, flags, indent,
                              braceindent + valindent, num, 0))
            confignode_dump_indent(fp, braceindent);
    }
    fputc(')', fp);
}

static void confignode_dumpintval(FILE *fp, struct ConfigIntValNode *n,
                                  unsigned flags)
{
    if (flags & CONFIG_FLAG_INT_PRINT_MODE_HEX)
        fprintf(fp, "%s = 0x%lx", n->base.key, n->value);
    else
        fprintf(fp, "%s = %lu", n->base.key, n->value);
}

static void confignode_dumpnumpair(FILE *fp, struct ConfigNumPairNode *n,
                                  unsigned flags)
{
    if (flags & CONFIG_FLAG_INT_PRINT_MODE_HEX)
        fprintf(fp, "0x%lx 0x%lx", n->value1, n->value2);
    else
        fprintf(fp, "%lu %lu", n->value1, n->value2);
}

static void confignode_dumpnumpairlist(FILE *fp,
                                       struct ConfigNumPairListNode *n,
                                       struct ConfigDumpCb *cb,
                                       unsigned flags, unsigned indent,
                                       unsigned curindent)
{
    struct ConfigBaseNode *i;
    int f, atbol = 1;

    fputs(n->base.key, fp);
    if (n->beforeFirst)
        atbol = confignode_dump_i(fp, n->beforeFirst, cb, flags, indent,
                                  curindent, 0, 0);
    if (!atbol)
        fputc('\n', fp);

    if (n->value) {
        confignode_foreach(i, n->value, f) {
            switch (i->type) {
            case CT_NUMPAIR:
                if (atbol)
                    confignode_dump_indent(fp, curindent + indent);
                atbol = 0;
                confignode_dumpnumpair(fp, confignode_to_numpair(i), flags);
                break;

            case CT_EOC:
                if (i->key) {
                    if (atbol)
                        fprintf(fp, "#%s", i->key);
                    else
                        fprintf(fp, " #%s", i->key);
                }
                fputc('\n', fp);
                atbol = 1;
                break;

            default:
                break;
            }
        }
    }
    if (!atbol)
        fputc('\n', fp);
    confignode_dump_indent(fp, curindent);
    fputs(n->end, fp);
}

static int confignode_dump_i(FILE *fp, struct ConfigBaseNode *n,
                             struct ConfigDumpCb *cb, unsigned flags,
                             unsigned indent, unsigned curindent,
                             unsigned numbares, int curatbol)
{
    struct ConfigBaseNode *i;
    int atbol = curatbol, newatbol;

    i = n;
    do {
        newatbol = 0;
        if (cb) {
            flags = cb->flags(i, flags);
        }
        if (atbol) {
            confignode_dump_indent(fp, curindent);
            if (curindent != 0)
                atbol = 0;
        } else if (i->type != CT_EOC) {
            /* In this case, we did not indent, but if a user writes
               multiple configurations in one line, we will
               concatenate value of previous item with key of new item
               producing an invalid configuration.  So add a space. */
            fputc(' ', fp);
        }

        switch (i->type) {
        case CT_FILEVERSION:
            fprintf(fp, "version %s", i->key);
            break;
        case CT_INTVAL:
            confignode_dumpintval(fp, confignode_to_intval(i), flags);
            break;
        case CT_STRINGVAL:
            fprintf(fp, "%s = \"%s\"", i->key,
                    confignode_to_stringval(i)->value);
            break;
        case CT_VERSIONVAL:
            fprintf(fp, "%s = %d.%d", i->key,
                    (confignode_to_versionval(i)->value & 0xffff0000) >> 16,
                    confignode_to_versionval(i)->value & 0xffff);
            break;
        case CT_BAREVAL:
            fprintf(fp, "%s = %s", i->key, confignode_to_bareval(i)->value);
            break;
        case CT_STRUCT:
            confignode_dumpstruct(fp, confignode_to_struct(i), cb, flags,
                                  indent, curindent);
            break;
        case CT_IDX_STRUCT:
            confignode_dumpidxstruct(fp, confignode_to_idxstruct(i), cb, flags,
                                     indent, curindent);
            break;
        case CT_BARELIST:
            confignode_dumpbarelist(fp, confignode_to_barelist(i), cb, flags,
                                    indent, curindent);
            break;
        case CT_EOC:
            if (i->key) {
                if (atbol)
                    fprintf(fp, "#%s", i->key);
                else
                    fprintf(fp, " #%s", i->key);
            }
            fputc('\n', fp);
            newatbol = 1;
            break;
        case CT_BARE:
            fputs(i->key, fp);
            if (numbares > 1) {
                fputc(',', fp);
                --numbares;
            } else if (i->next == n) {
                /* In this case, there is no EOL node after the last
                   element of the list.  Put a blank to separate it
                   from the closing bracket. */
                fputc(' ', fp);
            }
            break;
        case CT_BARECONST:
            fputs(i->key, fp);
            break;
        case CT_NUMPAIR:
            if (atbol)
                confignode_dump_indent(fp, curindent);
            confignode_dumpnumpair(fp, confignode_to_numpair(i), flags);
            break;
        case CT_NUMPAIRLIST:
            confignode_dumpnumpairlist(fp, confignode_to_numpairlist(i), cb,
                                       flags, indent, curindent);
            newatbol = 1;
            break;
        case CT_BARESTRINGCONST:
            fprintf(fp, "\"%s\"", i->key);
            break;
        default:
            break;
        }
        atbol = newatbol;
        i = i->next;
    } while (i != n);
    return atbol;
}

void confignode_dump(FILE *fp, struct ConfigBaseNode *n,
                     struct ConfigDumpCb *cb, unsigned indent)
{
    if (n)
        confignode_dump_i(fp, n, cb, 0, indent, 0, 0, 1);
}

/* dumpable allocations */
struct ConfigFileVersionNode *
confignode_allocfileversiondumpable(char *version, int line, char *comment)
{
    struct ConfigFileVersionNode *res;
    struct ConfigEOCNode *eoc;
    char *key, *cmt = NULL;

    key = strdup(version);
    if (!key)
        return NULL;
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(key);
            return NULL;
        }
    }
    res = confignode_allocfileversion(key, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freefileversion(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        free(key);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigIntValNode *
confignode_allocintvaldumpable(char *key, unsigned long val, int line,
                               char *comment)
{
    struct ConfigIntValNode *res;
    struct ConfigEOCNode *eoc;
    char *dkey, *cmt = NULL;

    dkey = strdup(key);
    if (!dkey)
        return NULL;
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(dkey);
            return NULL;
        }
    }
    res = confignode_allocintval(dkey, val, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freeintval(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigVersionValNode *
confignode_allocversionvaldumpable(char *key, unsigned long val, int line,
                                   char *comment)
{
    struct ConfigVersionValNode *res;
    struct ConfigEOCNode *eoc;
    char *dkey, *cmt = NULL;

    dkey = strdup(key);
    if (!dkey)
        return NULL;
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(dkey);
            return NULL;
        }
    }
    res = confignode_allocversionval(dkey, val, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freeversionval(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigStringValNode *
confignode_allocstringvaldumpable(char *key, char *val, int line, char *comment)
{
    struct ConfigStringValNode *res;
    struct ConfigEOCNode *eoc;
    char *str, *dkey, *cmt = NULL;

    dkey = strdup(key);
    str = strdup(val);
    if (!str || !dkey) {
        free(str);
        free(dkey);
        return NULL;
    }
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(str);
            free(dkey);
            return NULL;
        }
    }
    res = confignode_allocstringval(dkey, str, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freestringval(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        free(str);
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigBareValNode *
confignode_allocbarevaldumpable(char *key, char *val, int line, char *comment)
{
    struct ConfigBareValNode *res;
    struct ConfigEOCNode *eoc;
    char *str, *dkey, *cmt = NULL;

    dkey = strdup(key);
    str = strdup(val);
    if (!str || !dkey) {
        free(str);
        free(dkey);
        return NULL;
    }
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(str);
            free(dkey);
            return NULL;
        }
    }
    res = confignode_allocbareval(dkey, str, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freebareval(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        free(str);
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigIdxStructNode *
confignode_allocidxstructdumpable(char *key, unsigned long num,
                                  struct ConfigBaseNode *beforeOpen,
                                  struct ConfigBaseNode *value,
                                  int line, char *comment)
{
    struct ConfigIdxStructNode *res = NULL;
    struct ConfigEOCNode *eoc;
    char *dkey, *cmt = NULL;

    dkey = strdup(key);
    if (!dkey)
        return NULL;
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(dkey);
            return NULL;
        }
    }
    /* First allocate eoc node such that if allocating res fails, we do not
       take ownership of beforeOpen or value. */
    eoc = confignode_alloceoc(cmt, line);
    if (eoc) {
        res = confignode_allocidxstruct(dkey, num, beforeOpen, value, line);
        if (res) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freeeoc(eoc);
            if (cmt != NULL)
                free(cmt);
            free(dkey);
        }
    } else {
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}
struct ConfigStructNode *
confignode_allocstructdumpable(char *key,
                               struct ConfigBaseNode *beforeOpen,
                               struct ConfigBaseNode *value,
                               int line, char *comment)
{
    struct ConfigStructNode *res = NULL;
    struct ConfigEOCNode *eoc;
    char *dkey, *cmt = NULL;

    dkey = strdup(key);
    if (!dkey)
        return NULL;
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(dkey);
            return NULL;
        }
    }
    /* First allocate eoc node such that if allocating res fails, we do not
       take ownership of beforeOpen or value. */
    eoc = confignode_alloceoc(cmt, line);
    if (eoc) {
        res = confignode_allocstruct(dkey, beforeOpen, value, line);
        if (res) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freeeoc(eoc);
            if (cmt != NULL)
                free(cmt);
            free(dkey);
        }
    } else {
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigBareListNode *
confignode_allocbarelistdumpable(char *key,
                                 struct ConfigBaseNode *beforeOpen,
                                 struct ConfigBaseNode *value,
                                 int line, char *comment)
{
    struct ConfigBareListNode *res = NULL;
    struct ConfigEOCNode *eoc;
    char *dkey, *cmt = NULL;

    dkey = strdup(key);
    if (!dkey)
        return NULL;
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(dkey);
            return NULL;
        }
    }
    /* First allocate eoc node such that if allocating res fails, we do not
       take ownership of beforeOpen or value. */
    eoc = confignode_alloceoc(cmt, line);
    if (eoc) {
        res = confignode_allocbarelist(dkey, beforeOpen, value, line);
        if (res) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freeeoc(eoc);
            if (cmt != NULL)
                free(cmt);
            free(dkey);
        }
    } else {
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigBareNode *
confignode_allocbaredumpable(char *bareval, int line, char *comment)
{
    struct ConfigBareNode *res;
    struct ConfigEOCNode *eoc;
    char *dkey, *cmt = NULL;

    dkey = strdup(bareval);
    if (!dkey)
        return NULL;
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(dkey);
            return NULL;
        }
    }
    res = confignode_allocbare(dkey, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freebare(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigBareConstNode *
confignode_allocbareconstdumpable(char *key, int line, char *comment)
{
    struct ConfigBareConstNode *res;
    struct ConfigEOCNode *eoc;
    char *dkey, *cmt = NULL;

    dkey = strdup(key);
    if (!dkey)
        return NULL;
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(dkey);
            return NULL;
        }
    }
    res = confignode_allocbareconst(dkey, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freebareconst(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        free(dkey);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigNumPairNode *
confignode_allocnumpairdumpable(unsigned long value1, unsigned long value2,
                                int line, char *comment)
{
    struct ConfigNumPairNode *res;
    struct ConfigEOCNode *eoc;
    char *cmt = NULL;

    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL)
            return NULL;
    }
    res = confignode_allocnumpair(value1, value2, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freenumpair(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigNumPairListNode *
confignode_allocnumpairlistdumpable(char *key, char* end,
                                    struct ConfigBaseNode *beforeFirst,
                                    struct ConfigBaseNode *value,
                                    int line, char *comment)
{
    struct ConfigNumPairListNode *res = NULL;
    struct ConfigEOCNode *eoc;
    char *dkey, *dend, *cmt = NULL;

    dkey = strdup(key);
    if (!dkey)
        return NULL;
    dend = strdup(end);
    if (!dend) {
        free(dkey);
        return NULL;
    }
    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL) {
            free(dkey);
            free(dend);
            return NULL;
        }
    }
    /* First allocate eoc node such that if allocating res fails, we do not
       take ownership of beforeOpen or value. */
    eoc = confignode_alloceoc(cmt, line);
    if (eoc) {
        res = confignode_allocnumpairlist(dkey, dend, beforeFirst, value, line);
        if (res) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freeeoc(eoc);
            if (cmt != NULL)
                free(cmt);
            free(dkey);
            free(dend);
        }
    } else {
        free(dkey);
        free(dend);
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}

struct ConfigBareStringConstNode *
confignode_allocbarestringconstdumpable(char *key, int line, char *comment)
{
    struct ConfigBareStringConstNode *res;
    struct ConfigEOCNode *eoc;
    char *cmt = NULL;

    if (comment != NULL) {
        cmt = strdup(comment);
        if (cmt == NULL)
            return NULL;
    }
    res = confignode_allocbarestringconst(key, line);
    if (res) {
        eoc = confignode_alloceoc(cmt, line);
        if (eoc) {
            confignode_append(&(res->base), &(eoc->base));
        } else {
            confignode_freebarestringconst(res);
            if (cmt != NULL)
                free(cmt);
            res = NULL;
        }
    } else {
        if (cmt != NULL)
            free(cmt);
    }
    return res;
}
