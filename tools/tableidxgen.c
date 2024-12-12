/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#if defined(_AIX)
    const char *__progname = "tableidxgen";
#endif

#include "platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pkcs11types.h"

#define MECHTABLE_IN_GEN
#include <mechtable.h>
#undef MECHTABLE_IN_GEN

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

/* To satisfy symbols */
const struct mechtable_funcs mechtable_funcs;

int mechtable_idx_from_numeric(CK_ULONG mech)
{
    (void)mech;
    return -1;
}

int mechtable_idx_from_string(const char *mech)
{
    (void)mech;
    return -1;
}

const struct mechrow *mechrow_from_numeric(CK_ULONG mech)
{
    (void)mech;
    return NULL;
}

const struct mechrow *mechrow_from_string(const char *mech)
{
    (void)mech;
    return NULL;
}

/* A list of all aliases.  Add every non-unique mechanism number once
   to the table in mechtable.inc and add all aliases here.  The one in
   the table will be the one used in the string output. */
const struct aliaslist {
    const char *string;
    const char *alias;
} aliases[] = {
               { "CKM_ECDSA_KEY_PAIR_GEN", "CKM_EC_KEY_PAIR_GEN" },
               { "CKM_IBM_EC_C25519", "CKM_IBM_EC_X25519" },
               { "CKM_IBM_EC_C448", "CKM_IBM_EC_X448" },
               { "CKM_IBM_EDDSA_SHA512", "CKM_IBM_ED25519_SHA512" },
               { "CKM_SHA3_224_KEY_DERIVE", "CKM_SHA3_224_KEY_DERIVATION" },
               { "CKM_SHA3_256_KEY_DERIVE", "CKM_SHA3_256_KEY_DERIVATION" },
               { "CKM_SHA3_384_KEY_DERIVE", "CKM_SHA3_384_KEY_DERIVATION" },
               { "CKM_SHA3_512_KEY_DERIVE", "CKM_SHA3_512_KEY_DERIVATION" },
};

/* Get the table */
#include "mechtable.inc"

struct node;
struct node {
    short table[256];
    unsigned short num;
    unsigned int offset;
    unsigned int used;
    struct node *nextnum;
};

static unsigned char idxtable[256];
static unsigned char usagetable[256];
static unsigned int usagecount;
static unsigned short nextnum;
static struct node *root, **last;
static char *commonprefix;
static size_t commonprefixlength;

/* Utilities */
static struct node *getnodeforidx(short idx)
{
    short i;
    struct node *res = root;

    for (i = 0; i < idx; ++i)
        res = res->nextnum;
    return res;
}

static struct node *allocatenode(void)
{
    struct node *res = malloc(sizeof(struct node));

    if (!res)
        errx(1, "Failed to allocate node");
    res->num = nextnum++;
    res->nextnum = NULL;
    res->used = 0;
    res->offset = 0;
    *last = res;
    memset(res->table, 0, 256 * sizeof(short));
    last = &(res->nextnum);
    return res;
}

static void freenodes(void)
{
    struct node *i, *n;

    for (i = root; i; i = n) {
        n = i->nextnum;
        free(i);
    }
}

static void reinitializenodes(void)
{
    freenodes();
    root = NULL;
    last = &root;
    nextnum = 0;
    allocatenode();
}

/* Additions */
static void addnumeric(const struct mechrow *m, short position)
{
    short idx;
    struct node *n = root, *a;

    idx = (m->numeric & 0xff000000u) >> 24u;
    if (n->table[idx] == 0) {
        a = allocatenode();
        n->table[idx] = a->num;
        n->used += 1;
        n = a;
    } else {
        n = getnodeforidx(n->table[idx]);
    }
    idx = (m->numeric & 0x00ff0000u) >> 16u;
    if (n->table[idx] == 0) {
        a = allocatenode();
        n->table[idx] = a->num;
        n->used += 1;
        n = a;
    } else {
        n = getnodeforidx(n->table[idx]);
    }
    idx = (m->numeric & 0x0000ff00u) >> 8u;
    if (n->table[idx] == 0) {
        a = allocatenode();
        n->table[idx] = a->num;
        n->used += 1;
        n = a;
    } else {
        n = getnodeforidx(n->table[idx]);
    }
    idx = m->numeric & 0x000000ffu;
    if (n->table[idx]) {
        errx(1, "Duplicated key 0x%lx.  Please use aliaslist in tableidxgen.c for duplicates\n",
             m->numeric);
        return;
    }
    /* Make sure we do not insert zero.  Zero marks an empty cell. */
    n->table[idx] = -position - 1;
    n->used += 1;
}

static short recursiveaddstring(const char *str, short position)
{
    size_t len = strlen(str);
    size_t i;
    struct node *n = root, *a;
    short val, readd = 0, idx;

    for (i = commonprefixlength; i <= len; ++i) {
        idx = str[i];
        val = n->table[idx];
        if (val > 0) {
            /* A link */
            n = getnodeforidx(val);
        } else if (val == 0) {
            /* An empty slot */
            n->table[idx] = -position - 1;
            n->used += 1;
            return readd;
        } else {
            /* A value */
            readd = val;
            /* Duplication check */
            if (strcmp(str, mechtable_rows[-val - 1].string) == 0)
                errx(1, "Dublicated string keys (%s) not supported!", str);
            a = allocatenode();
            n->table[idx] = a->num;
            n->used += 1;
            n = a;
        }
    }
    /* I don't see how this can happen, but the compiler disagrees. */
    errx(1, "Cannot add key %s!", str);
}

static void addstring(const struct mechrow *m, short position)
{
    short res = position;
    const struct mechrow *toadd = m;

    while ((res = recursiveaddstring(toadd->string, res)) < 0) {
        res = -res - 1;
        toadd = &mechtable_rows[res];
    }
}

/* Compressors */
static void compressnumericalphabet(void)
{
    size_t i;
    unsigned int idx;

    memset(usagetable, 0, 256);
    memset(idxtable, 0, 256);
    usagecount = 0;
    for (i = 0; i < ARRAY_SIZE(mechtable_rows); ++i) {
        idx = (mechtable_rows[i].numeric & 0xff000000u) >> 24u;
        if (usagetable[idx] == 0)
            ++usagecount;
        usagetable[idx] = 1;
        idx = (mechtable_rows[i].numeric & 0x00ff0000u) >> 16u;
        if (usagetable[idx] == 0)
            ++usagecount;
        usagetable[idx] = 1;
        idx = (mechtable_rows[i].numeric & 0x0000ff00u) >> 8u;
        if (usagetable[idx] == 0)
            ++usagecount;
        usagetable[idx] = 1;
        idx = (mechtable_rows[i].numeric & 0x000000ffu);
        if (usagetable[idx] == 0)
            ++usagecount;
        usagetable[idx] = 1;
    }
    idx = 0;
    for (i = 0; i < 256; ++i) {
        if (usagetable[i])
            idxtable[i] = (unsigned char)idx++;
    }
}

static void compressstringalphabet(void)
{
    size_t i, j;
    unsigned int idx;  

    memset(usagetable, 0, 256);
    memset(idxtable, 0, 256);
    usagecount = 0;
    for (i = 0; i < ARRAY_SIZE(mechtable_rows); ++i) {
        for (j = 0; j <= strlen(mechtable_rows[i].string); ++j) {
            idx = mechtable_rows[i].string[j];
            if (usagetable[idx] == 0)
                ++usagecount;
            usagetable[idx] = 1;
        }
    }
    idx = 0;
    for (i = 0; i < 256; ++i) {
        if (usagetable[i])
            idxtable[i] = (unsigned char)idx++;
    }  
}

static unsigned int compresstable(void)
{
    int pos, i, k, l;
    struct node *n;
    unsigned int maxoffset = 0;
    unsigned int offset;
    /* allocate properly too much */
    unsigned char *t = calloc(nextnum, usagecount);
    struct node **sorttable = calloc(nextnum, sizeof(struct node *));

    if (!t)
        errx(1, "Could not allocate compression table");
    if (!sorttable)
        errx(1, "Could not allocate sort table");
    pos = 0;
    /* sort nodes by used count (descending) */
    for (n = root; n; n = n->nextnum) {
        for (i = 0; i < pos; ++i) {
            if (n->used > sorttable[i]->used) {
                memmove(sorttable + i + 1, sorttable + i,
                        (pos - i) * sizeof(struct node *));
                break;
            }
        }
        sorttable[i] = n;
        ++pos;
    }
    assert(pos == nextnum);
    /* now insert and compress */
    /* for all nodes */
    for (i = 0; i < nextnum; ++i) {
        /* for all possible offsets */
        for (offset = 0; offset < (nextnum - 1) * usagecount; ++offset) {
            /* try to put table i at offset */
            for (k = 0; k < 256; ++k) {
                if (usagetable[k] && sorttable[i]->table[k]) {
                    if (t[idxtable[k] + offset])
                        break;
                    t[idxtable[k] + offset] = 1;
                }
            }
            if (k == 256) {
                /* success for node i */
                sorttable[i]->offset = offset;
                if (offset > maxoffset)
                    maxoffset = offset;
                break;
            } else {
                /* failure => undo t updates */
                for (l = 0; l < k; ++l) {
                    if (usagetable[l] && sorttable[i]->table[l])
                        t[idxtable[l] + offset] = 0;
                }
            }
        }
    }
    free(sorttable);
    free(t);
    return maxoffset;
}

/* Common prefix elimination */
static void eliminatecommonprefixes(void)
{
    size_t i, j, minlength, l;

    commonprefix = strdup(mechtable_rows[0].string);
    if (!commonprefix)
        errx(1, "Out of memory");
    commonprefixlength = strlen(commonprefix);
    for (i = 1; i < ARRAY_SIZE(mechtable_rows); ++i) {
        l = strlen(mechtable_rows[i].string);
        minlength = commonprefixlength < l ? commonprefixlength : l;
        for (j = 0; j < minlength &&
                 commonprefix[j] == mechtable_rows[i].string[j]; ++j) {
            /* Advance */
        }
        commonprefix[j] = 0;
        commonprefixlength = j;
    }
}

/* Builders */
static void buildnumeric(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(mechtable_rows); ++i)
        addnumeric(&mechtable_rows[i], i);
}

static void buildstring(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(mechtable_rows); ++i)
        addstring(&mechtable_rows[i], i);
}

static short *buildcompressedtable(unsigned int maxoffset)
{
    struct node *n;
    unsigned int i, idx;
    short *res = calloc(maxoffset + usagecount, sizeof(short));

    if (!res)
        errx(1, "Could not allocate compressed table");
    for (n = root; n; n = n->nextnum) {
        for (i = 0; i < 256; ++i) {
            if (usagetable[i] && n->table[i]) {
                idx = idxtable[i] + n->offset;
                assert(res[idx] == 0);
                if (n->table[i] < 0)
                    /* a value */
                    res[idx] = n->table[i];
                else
                    /* a link */
                    res[idx] = getnodeforidx(n->table[i])->offset;
            }
        }
    }
    return res;
}

static void freecompressedtable(short *table)
{
    free(table);
}

/* Logging */
static void lognodes(FILE *fp)
{
    struct node *n;
    int i;

    fputs("Jump table:\n", fp);
    for (n = root; n; n = n->nextnum) {
        fprintf(fp, "node %hu: (offset %u)\n", n->num, n->offset);
        for (i = 0; i < 256; ++i) {
            if (n->table[i] > 0)
                fprintf(fp, "  %d (%d) => node %hd\n", i, (int)idxtable[i],
                        n->table[i]);
            else if (n->table[i] < 0)
                fprintf(fp, "  %d (%d) => mapping %d\n", i, (int)idxtable[i],
                        -(n->table[i]+1));
        }
    }
}

static FILE *openfile(char *name)
{
    FILE *res = fopen(name, "w");

    if (!res)
        err(1, "Failed to open %s", name);
    return res;
}

static void closefile(FILE *fp)
{
    fclose(fp);
}

static void logalphabet(FILE *fp)
{
    int i;

    fputs("Alphabet mapping:\n", fp);
    for (i = 0; i < 256; ++i) {
        if (usagetable[i])
            fprintf(fp, "%c (%d) => %hhu\n", (char)i, i, idxtable[i]);
    }
}

/* dumpers */
static void dumptable(unsigned int maxoffset, short *table, char *name,
                      FILE *fp)
{
    unsigned int i, j;

    fprintf(fp, "static const short %stable[] = {\n", name);
    for (i = 0; i < (maxoffset + usagecount) / 8; ++i) {
        fprintf(fp, "  %hd, %hd, %hd, %hd, %hd, %hd, %hd, %hd,\n",
                table[8 * i], table[8 * i + 1], table[8 * i + 2],
                table[8 * i + 3], table[8 * i + 4], table[8 * i + 5],
                table[8 * i + 6], table[8 * i + 7]);
    }
    if ((maxoffset + usagecount) % 8 != 0) {
        fputc(' ', fp);
        for (j = 0; j < (maxoffset + usagecount) % 8; ++j) {
            fprintf(fp, " %hd,", table[8 * i + j]);
        }
        fputc('\n', fp);
    }
    fputs("};\n", fp);
}

static void dumpalphabet(char *name, FILE *fp)
{
    int i;

    fprintf(fp, "static const unsigned char %salphabet[] = {\n", name);
    for (i = 0; i < 256 / 8; ++i) {
        fprintf(fp, "  %hhu, %hhu, %hhu, %hhu, %hhu, %hhu, %hhu, %hhu,\n",
                idxtable[8 * i], idxtable[8 * i + 1], idxtable[8 * i + 2],
                idxtable[8 * i + 3], idxtable[8 * i + 4], idxtable[8 * i + 5],
                idxtable[8 * i + 6], idxtable[8 * i + 7]);
    }
    fputs("};\n", fp);
}

static void dumpnumericfun(FILE *fp)
{
    fputs("int mechtable_idx_from_numeric(CK_ULONG mech)\n", fp);
    fputs("{\n", fp);
    fputs("    unsigned int idx1, idx2, idx3, idx4;\n", fp);
    fputs("    int o1, o2, o3;\n", fp);
    fputs("    int midx;\n\n", fp);
    fputs("    idx1 = numericalphabet[(mech & 0xff000000u) >> 24u];\n", fp);
    fputs("    idx2 = numericalphabet[(mech & 0x00ff0000u) >> 16u];\n", fp);
    fputs("    idx3 = numericalphabet[(mech & 0x0000ff00u) >> 8u];\n", fp);
    fputs("    idx4 = numericalphabet[mech & 0x000000ffu];\n", fp);
    /* No need to check idx vars since they are 0 if unsigned char is not mapped
       and nothing problematic happens.  The search will just be
       unsuccessful. */
    fprintf(fp, "    o1 = numerictable[%u + idx1];\n", root->offset);
    fputs("    if (o1 < 0) return -1;\n", fp);
    fputs("    o2 = numerictable[o1 + idx2];\n", fp);
    fputs("    if (o2 < 0) return -1;\n", fp);
    fputs("    o3 = numerictable[o2 + idx3];\n", fp);
    fputs("    if (o3 < 0) return -1;\n", fp);
    fputs("    midx = numerictable[o3 + idx4];\n", fp);
    fputs("    midx = -(midx + 1);\n", fp);
    fprintf(fp, "    if (0 <= midx && midx < %zu && mechtable_rows[midx].numeric == mech)\n",
            ARRAY_SIZE(mechtable_rows));
    fputs("        return midx;\n", fp);
    fputs("    return -1;\n", fp);
    fputs("}\n\n", fp);
    fputs("const struct mechrow *mechrow_from_numeric(CK_ULONG mech)\n", fp);
    fputs("{\n", fp);
    fputs("    int idx = mechtable_idx_from_numeric(mech);\n", fp);
    fputs("\n", fp);
    fputs("    if (idx < 0)\n", fp);
    fputs("        return NULL;\n", fp);
    fputs("    return &mechtable_rows[idx];\n", fp);
    fputs("}\n\n", fp);
}

static void dumpstringfun(FILE *fp)
{
    size_t i;

    fprintf(fp, "static const size_t commonprefixlength = %zu;\n\n",
            commonprefixlength);
    fputs("int mechtable_idx_from_string(const char *mech)\n", fp);
    fputs("{\n", fp);
    fputs("    static const struct {\n", fp);
    fputs("        const char *string;\n", fp);
    fputs("        const char *alias;\n", fp);
    fputs("    } aliaslist[] = {\n", fp);
    for (i = 0; i < ARRAY_SIZE(aliases); ++i) {
        fprintf(fp, "        { \"%s\", \"%s\" },\n",
                aliases[i].string, aliases[i].alias);
    }
    fputs("    };\n", fp);
    fputs("    size_t len = strlen(mech), i;\n", fp);
    fprintf(fp, "    short idx = %u;\n", root->offset);
    fputs("    unsigned char h;\n\n", fp);
    fputs("    for (i = commonprefixlength; i <= len; ++i) {\n", fp);
    fputs("        h = stringalphabet[(int)mech[i]];\n", fp);
    /* No need to check the h since they are 0 if unsigned char is not mapped
       and nothing problematic happens.  The search will just be
       unsuccessful. */
    fputs("        idx = stringtable[idx + h];\n", fp);
    fputs("        if (idx < 0) {\n", fp);
    fputs("            idx = -(idx + 1);\n", fp);
    fputs("            if (strcmp(mech, mechtable_rows[idx].string) == 0)\n",
          fp);
    fputs("                return idx;\n", fp);
    fputs("            goto outcheckaliases;\n", fp);
    fputs("        }\n", fp);
    fputs("    }\n", fp);
    fputs("  outcheckaliases:\n", fp);
    fputs("    for (i = 0; i < sizeof(aliaslist) / sizeof(aliaslist[0]); ++i) {\n",
          fp);
    fputs("        if (strcmp(aliaslist[i].string, mech) == 0)\n", fp);
    fputs("            return mechtable_idx_from_string(aliaslist[i].alias);\n",
          fp);
    fputs("    }\n", fp);
    fputs("    return -1;\n", fp);
    fputs("}\n\n", fp);
    fputs("const struct mechrow *mechrow_from_string(const char *mech)\n", fp);
    fputs("{\n", fp);
    fputs("    int idx = mechtable_idx_from_string(mech);\n\n", fp);
    fputs("    if (idx < 0)\n", fp);
    fputs("        return NULL;\n", fp);
    fputs("    return &mechtable_rows[idx];\n", fp);
    fputs("}\n\n", fp);
}

static void generatelicense(FILE *fp)
{
    time_t t;
    struct tm *tm;
    char *tstr;

    t = time(NULL);
    tm = localtime(&t);
    tstr = asctime(tm);
    /* Remove trailing newline character */
    tstr[strlen(tstr) - 1] = 0;
    fputs("/*\n", fp);
    fprintf(fp, " * COPYRIGHT (c) International Business Machines Corp. 2024\n");
    fputs(" *\n", fp);
    fputs(" * This program is provided under the terms of the Common Public License,\n",
          fp);
    fputs(" * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this\n",
          fp);
    fputs(" * software constitutes recipient's acceptance of CPL-1.0 terms which can be\n",
          fp);
    fputs(" * found in the file LICENSE file or at\n", fp);
    fputs(" * https://opensource.org/licenses/cpl1.0.php\n", fp);
    fputs(" */\n", fp);
    fprintf(fp, "/* AUTO-GENERATED on %s.  DO NOT EDIT! */\n\n", tstr);
}

static void generateheader(char *hname)
{
    FILE *fp = openfile(hname);

    generatelicense(fp);
    fputs("#ifndef OCK_MECHTABLE_GEN_H\n", fp);
    fputs("#define OCK_MECHTABLE_GEN_H\n\n", fp);
    fprintf(fp, "#define MECHTABLE_NUM_ELEMS %zu\n\n", ARRAY_SIZE(mechtable_rows));
    fputs("#endif\n\n", fp);
    closefile(fp);
}

static void dumpmechtableaccessors(FILE *fp)
{
    fputs("const struct mechtable_funcs mechtable_funcs = {\n", fp);
    fputs("    .p_idx_from_num = &mechtable_idx_from_numeric,\n", fp);
    fputs("    .p_idx_from_str = &mechtable_idx_from_string,\n", fp);
    fputs("    .p_row_from_num = &mechrow_from_numeric,\n", fp);
    fputs("    .p_row_from_str = &mechrow_from_string\n", fp);
    fputs("};\n\n", fp);
}

static void usage(char *name, int exitcode)
{
    printf("USAGE: %s [-l|--log <name>] [-c|--cfile <name>] [-d|-dname <name>]\n",
           name);
    puts("where:");
    puts("\t-l|--log   specifies the destination of the log file");
    puts("\t-c|--cname specifies the destination of the generated c file");
    puts("\t-d|--dname specifies the destination of the generated header file");
    puts("\t-h|--help  prints this help and exits");
    puts("All arguments are mandatory!");
    exit(exitcode);
}

static void parseargs(int argc, char **argv, char **lname, char **cname,
                      char **hname)
{
    char *progname = argv[0];
    int c;
    static struct option long_options[] =
        {
         { "log",   required_argument, 0, 'l' },
         { "cname", required_argument, 0, 'c' },
         { "dname", required_argument, 0, 'd' },
         { "help",  no_argument,       0, 'h' },
         { 0,       0,                 0, 0   }
        };
    while (1) {
        c = getopt_long(argc, argv, "l:c:d:h", long_options, NULL);
        if (c == -1)
            break;
        switch(c) {
        case 'l':
            *lname = optarg;
            break;
        case 'c':
            *cname = optarg;
            break;
        case 'd':
            *hname = optarg;
            break;
        case 'h':
            usage(progname, 0);
            break;
        default:
            usage(progname, 1);
            break;
        }
    }
    if (optind < argc)
        /* Superfluous arguments */
        usage(progname, 1);
}

int main(int argc, char **argv)
{
    short *table;
    unsigned int maxoffset;
    FILE *logfp, *cfp;
    char *logname = 0, *cname = 0, *hname = 0;

    parseargs(argc, argv, &logname, &cname, &hname);
    if (!logname || !cname || !hname)
        usage(argv[0], 1);
    logfp = openfile(logname);
    cfp = openfile(cname);

    generateheader(hname);

    generatelicense(cfp);
    fputs("#include <string.h>\n", cfp);
    fputs("#include <pkcs11types.h>\n", cfp);
    fputs("#include \"mechtable.h\"\n", cfp);
    fputs("#include \"mechtable.inc\"\n\n", cfp);
    eliminatecommonprefixes();
    reinitializenodes();
    buildnumeric();
    compressnumericalphabet();
    maxoffset = compresstable();
    table = buildcompressedtable(maxoffset);
    dumpalphabet("numeric", cfp);
    dumptable(maxoffset, table, "numeric", cfp);
    dumpnumericfun(cfp);
    freecompressedtable(table);
    fputs("Numeric table:\n", logfp);
    logalphabet(logfp);
    lognodes(logfp);
  
    reinitializenodes();
    buildstring();
    compressstringalphabet();
    maxoffset = compresstable();
    table = buildcompressedtable(maxoffset);
    dumpalphabet("string", cfp);
    dumptable(maxoffset, table, "string", cfp);
    dumpstringfun(cfp);
    freecompressedtable(table);
    fputs("\nString table:\n", logfp);
    logalphabet(logfp);
    lognodes(logfp);

    dumpmechtableaccessors(cfp);

    closefile(logfp);
    closefile(cfp);
    free(commonprefix);
    freenodes();
    return 0;
}
