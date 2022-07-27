/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <uri.h>
#include "unittest.h"

#define BUFLEN         128

#define MIN(a, b)      (a < b) ? (a) : (b)
#define BINIT(s, e)    memset(s.e, ' ', sizeof(s.e))
#define SCPY(s, e, c)  _cpy(s.e, sizeof(s.e), c)

static CK_INFO i;
static CK_SLOT_INFO s;
static CK_TOKEN_INFO t;

static CK_OBJECT_CLASS cko_data = CKO_DATA;
static CK_OBJECT_CLASS cko_pubk = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS cko_cert = CKO_CERTIFICATE;
static CK_OBJECT_CLASS cko_prvk = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS cko_seck = CKO_SECRET_KEY;

static CK_CHAR ckc_id_buf[BUFLEN];
static CK_CHAR ckc_label_buf[BUFLEN];

static void _cpy(unsigned char *dest, size_t d_len, char *src)
{
    size_t s_len;

    if (!src)
        return;

    s_len = strlen(src);
    memcpy(dest, src, MIN(s_len, d_len));
}

static void _gen_uri(struct p11_uri *uri,
                     char *i_dsc, char *i_man, int i_vmj, int i_vmi,
                     int s_id, char *s_dsc, char *s_man,
                     char *t_lbl, char *t_man, char *t_mod, char *t_ser,
                     char *o_id, char *o_lbl, CK_OBJECT_CLASS_PTR o_type)
{
    /* initialize string fields */
    BINIT(i, manufacturerID);
    BINIT(i, libraryDescription);

    BINIT(s, manufacturerID);
    BINIT(s, slotDescription);

    BINIT(t, label);
    BINIT(t, manufacturerID);
    BINIT(t, model);
    BINIT(t, serialNumber);

    /* initialize attribute templates */
    memset(ckc_id_buf,    '\0', BUFLEN);
    memset(ckc_label_buf, '\0', BUFLEN);

    /* info */
    SCPY(i, manufacturerID,     i_man);
    SCPY(i, libraryDescription, i_dsc);
    i.libraryVersion.major = i_vmj;
    i.libraryVersion.minor = i_vmi;

    /* slot */
    uri->slot_id = -1;
    if (s_id >= 0)
        uri->slot_id = s_id;
    SCPY(s, manufacturerID,  s_man);
    SCPY(s, slotDescription, s_dsc);

    /* token */
    SCPY(t, label,          t_lbl);
    SCPY(t, manufacturerID, t_man);
    SCPY(t, model,          t_mod);
    SCPY(t, serialNumber,   t_ser);

    uri->info = NULL;
    if (i_man || i_dsc)
        uri->info = &i;

    uri->slot_info = NULL;
    if (s_man || s_dsc)
        uri->slot_info = &s;

    uri->token_info = NULL;
    if (t_lbl || t_man || t_mod || t_ser)
        uri->token_info = &t;

    if (o_type) {
        uri->obj_class[0].type = CKA_CLASS;
        uri->obj_class[0].pValue = o_type;
        uri->obj_class[0].ulValueLen = sizeof(CK_OBJECT_CLASS);
    }
    if (o_id) {
        memcpy(ckc_id_buf, o_id, strlen(o_id));
        uri->obj_id[0].type = CKA_ID;
        uri->obj_id[0].pValue = ckc_id_buf;
        uri->obj_id[0].ulValueLen = strlen(o_id);
    }
    if (o_lbl) {
        memcpy(ckc_label_buf, o_lbl, strlen(o_lbl));
        uri->obj_label[0].type = CKA_LABEL;
        uri->obj_label[0].pValue = ckc_label_buf;
        uri->obj_label[0].ulValueLen = strlen(o_lbl);
    }
}

static void _alloc_attr(CK_ATTRIBUTE_PTR attr)
{
    attr->pValue = malloc(8);
    if (!attr->pValue)
        return;
    attr->ulValueLen = 8;
}

static void _alloc_attrs(struct p11_uri *uri)
{
    _alloc_attr(&uri->obj_id[0]);
    _alloc_attr(&uri->obj_label[0]);
    _alloc_attr(&uri->obj_class[0]);
}

static int test_uri_base(void)
{
    int result = 0;
    struct p11_uri *uri;

    uri = p11_uri_new();
    if (!uri)
        return 1;
    if ((uri == NULL) ||
        (uri->priv == NULL)) {
        fprintf(stderr, "[%d] %s: %s\n",
                0, "p11_uri_new()",
                "wrong initial uri values");
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    _alloc_attrs(uri);
    p11_uri_attributes_free(uri);
    if ((uri->obj_id[0].pValue)    || (uri->obj_id[0].ulValueLen)    ||
        (uri->obj_label[0].pValue) || (uri->obj_label[0].ulValueLen) ||
        (uri->obj_class[0].pValue) || (uri->obj_class[0].ulValueLen)) {
        fprintf(stderr, "[%d] %s: %s\n",
                1, "p11_uri_attributes_free()",
                "wrong uri attribute values after free");
        result++;
    }
    p11_uri_free(uri);

    return result;
}

static int test_uri_format()
{
    int result = 0;
    const char *cur_uri, *exp_uri;
    struct p11_uri *uri;

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:library-description=testLib;library-manufacturer=ACME;library-version=47.11";
    _gen_uri(uri,
             "testLib", "ACME", 47, 11,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             NULL, NULL, NULL);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                0, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:slot-id=0;slot-description=testslot;slot-manufacturer=ACME";
    _gen_uri(uri,
             NULL, NULL, -1, -1,
             0, "testslot", "ACME",
             NULL, NULL, NULL, NULL,
             NULL, NULL, NULL);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                1, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:manufacturer=ACME;model=TestModel;serial=0123456789;token=testtok";
    _gen_uri(uri,
             NULL, NULL, -1, -1,
             -1, NULL, NULL,
             "testtok", "ACME", "TestModel", "0123456789",
             NULL, NULL, NULL);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                2, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:id=%30%31%32%33%34%35%36%37%38%39%61%62%63;object=testo_data;type=data";
    _gen_uri(uri,
             NULL, NULL, -1, -1,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             "0123456789abc", "testo_data", &cko_data);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                3, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:id=%30%31%32%33%34%35%36%37%38%39%61%62%63;object=testo_privk;type=private";
    _gen_uri(uri,
             NULL, NULL, -1, -1,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             "0123456789abc", "testo_privk", &cko_prvk);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                4, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:id=%30%31%32%33%34%35%36%37%38%39%61%62%63;object=testo_pubk;type=public";
    _gen_uri(uri,
             NULL, NULL, -1, -1,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             "0123456789abc", "testo_pubk", &cko_pubk);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                5, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:id=%30%31%32%33%34%35%36%37%38%39%61%62%63;object=testo_seck;type=secret-key";
    _gen_uri(uri,
             NULL, NULL, -1, -1,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             "0123456789abc", "testo_seck", &cko_seck);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                6, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:id=%30%31%32%33%34%35%36%37%38%39%61%62%63;object=testo_cert;type=cert";
    _gen_uri(uri,
             NULL, NULL, -1, -1,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             "0123456789abc", "testo_cert", &cko_cert);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                7, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:";
    _gen_uri(uri,
             NULL, NULL, -1, -1,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             NULL, NULL, NULL);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                8, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    return result;
}

static int test_uri_encode()
{
    int result = 0;
    const char *cur_uri, *exp_uri;
    struct p11_uri *uri;

    /* common non-encode characters */
    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:library-description=abcdefghijklmnopqrstuvwxyz;library-manufacturer=ACME;library-version=47.11";
    _gen_uri(uri,
             "abcdefghijklmnopqrstuvwxyz", "ACME", 47, 11,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             NULL, NULL, NULL);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                0, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:library-description=ABCDEFGHIJKLMNOPQRSTUVWXYZ;library-manufacturer=ACME;library-version=47.11";
    _gen_uri(uri,
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ACME", 47, 11,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             NULL, NULL, NULL);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                1, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:library-description=0123456789_-.;library-manufacturer=ACME;library-version=47.11";
    _gen_uri(uri,
             "0123456789_-.", "ACME", 47, 11,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             NULL, NULL, NULL);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                2, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    /* reserved non-encode characters */
    uri = p11_uri_new();
    if (!uri)
        return 1;
    exp_uri = "pkcs11:library-description=:[]@!$\'()*+,=;library-manufacturer=ACME;library-version=47.11";
    _gen_uri(uri,
             ":[]@!$\'()*+,=", "ACME", 47, 11,
             -1, NULL, NULL,
             NULL, NULL, NULL, NULL,
             NULL, NULL, NULL);
    cur_uri = p11_uri_format(uri);
    if (strcmp(cur_uri, exp_uri) != 0) {
        fprintf(stderr,"[%d] p11_uri_format(): curr: %s, expected: %s\n",
                3, cur_uri, exp_uri);
        result++;
    }
    p11_uri_free(uri);

    return result;
}

int main(void)
{
    if (test_uri_base())
        return TEST_FAIL;
    if (test_uri_format())
        return TEST_FAIL;
    if (test_uri_encode())
        return TEST_FAIL;

    return TEST_PASS;
}
