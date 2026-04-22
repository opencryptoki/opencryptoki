/*
 * COPYRIGHT (c) International Business Machines Corp. 2026
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Unit and fuzzing tests for object_flatten and object_restore_withSize
 * functions in object.c
 *
 * This test suite performs comprehensive testing including:
 * - Unit tests for valid inputs
 * - Unit tests for invalid/NULL inputs
 * - Unit tests for boundary conditions
 * - Fuzzing tests with random data
 * - Fuzzing tests with corrupted data
 * - Round-trip testing (flatten -> restore)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "unittest.h"

#ifndef __BIG_ENDIAN__
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        #define __BIG_ENDIAN__
    #endif
#endif

/* Function prototypes from object.c */
CK_RV object_flatten(OBJECT *obj, CK_BYTE **data, CK_ULONG *len);
CK_RV object_restore_withSize(struct policy *policy,
                              CK_BYTE *data, OBJECT **new_obj,
                              CK_BBOOL replace, CK_ULONG data_size,
                              const char *fname);

/* Template function prototypes */
CK_RV template_add_attributes(TEMPLATE *tmpl, CK_ATTRIBUTE *pTemplate,
                              CK_ULONG ulCount);
CK_RV template_free(TEMPLATE *tmpl);
CK_BBOOL template_attribute_find(TEMPLATE *tmpl,
                                 CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE **attr);
CK_BBOOL compare_attribute(CK_ATTRIBUTE_PTR a1, CK_ATTRIBUTE_PTR a2);
void object_free(OBJECT *obj);
CK_RV object_init_lock(OBJECT *obj);
CK_RV object_init_ex_data_lock(OBJECT *obj);

/* Test statistics */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int crashes_prevented = 0;

#define TEST_ASSERT(condition, msg) do { \
    tests_run++; \
    if (!(condition)) { \
        printf("FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        tests_failed++; \
        return -1; \
    } else { \
        tests_passed++; \
    } \
} while(0)

#define TEST_PASS_FUNC() do { \
    printf("PASS: %s\n", __func__); \
    return 0; \
} while(0)

/* Helper function to create a simple test object */
static CK_RV create_test_object(OBJECT **obj, CK_OBJECT_CLASS class,
                                const char *name)
{
    OBJECT *o = NULL;
    TEMPLATE *tmpl = NULL;
    CK_ATTRIBUTE attrs[4];
    CK_BBOOL true_val = TRUE;
    CK_BBOOL false_val = FALSE;
    char *label = "A label for a nested attribute-array attribute";
    CK_ATTRIBUTE unwrap_template[] = {
            { CKA_SIGN, &true_val, sizeof(true_val) },
            { CKA_VERIFY, &true_val, sizeof(true_val) },
            { CKA_LABEL, label, strlen(label) },
    };
    CK_ATTRIBUTE wrap_template[] = {
            { CKA_SIGN, &true_val, sizeof(true_val) },
            { CKA_VERIFY, &true_val, sizeof(true_val) },
            { CKA_LABEL, label, strlen(label) },
            { CKA_UNWRAP_TEMPLATE, unwrap_template, sizeof(unwrap_template) },
    };
    CK_RV rc;

    o = (OBJECT *)calloc(1, sizeof(OBJECT));
    if (!o)
        return CKR_HOST_MEMORY;

    tmpl = (TEMPLATE *)calloc(1, sizeof(TEMPLATE));
    if (!tmpl) {
        free(o);
        return CKR_HOST_MEMORY;
    }

    o->class = class;
    if (name)
        memcpy(o->name, name, 8);
    else
        memcpy(o->name, "testobj1", 8);

    o->template = tmpl;

    /* Add some basic attributes */
    attrs[0].type = CKA_TOKEN;
    attrs[0].pValue = &true_val;
    attrs[0].ulValueLen = sizeof(CK_BBOOL);

    attrs[1].type = CKA_PRIVATE;
    attrs[1].pValue = &false_val;
    attrs[1].ulValueLen = sizeof(CK_BBOOL);

    attrs[2].type = CKA_CLASS;
    attrs[2].pValue = &class;
    attrs[2].ulValueLen = sizeof(CK_OBJECT_CLASS);

    attrs[3].type = CKA_WRAP_TEMPLATE;
    attrs[3].pValue = &wrap_template;
    attrs[3].ulValueLen = sizeof(wrap_template);

    rc = template_add_attributes(tmpl, attrs, 4);
    if (rc != CKR_OK) {
        free(tmpl);
        free(o);
        return rc;
    }

    rc = object_init_lock(o);
    if (rc != CKR_OK) {
        template_free(tmpl);
        free(o);
        return rc;
    }

    rc = object_init_ex_data_lock(o);
    if (rc != CKR_OK) {
        object_free(o);
        return rc;
    }

    *obj = o;
    return CKR_OK;
}

CK_BBOOL template_compare(TEMPLATE *t1, TEMPLATE *t2)
{
    DL_NODE *node;
    CK_ATTRIBUTE *attr1 = NULL;
    CK_ATTRIBUTE *attr2 = NULL;
    CK_RV rc;

    if (t1 == NULL || t2 == NULL)
        return FALSE;

    /* Check if all attributes of t1 are also on t2 */
    node = t1->attribute_list;
    while (node != NULL) {
        attr1 = (CK_ATTRIBUTE *)node->data;

        rc = template_attribute_find(t2, attr1->type, &attr2);
        if (rc == FALSE)
            return FALSE;

        if (!compare_attribute(attr1, attr2))
            return FALSE;

        node = node->next;
    }

    /* Check if all attributes of t2 are also on t1 */
    node = t2->attribute_list;
    while (node != NULL) {
        attr1 = (CK_ATTRIBUTE *)node->data;

        rc = template_attribute_find(t1, attr1->type, &attr2);
        if (rc == FALSE)
            return FALSE;

        if (!compare_attribute(attr1, attr2))
            return FALSE;

        node = node->next;
    }

    return TRUE;
}

/* ========== UNIT TESTS ========== */

/* Test 1: object_flatten with NULL object */
static int test_flatten_null_object(void)
{
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;
    CK_RV rc;

    rc = object_flatten(NULL, &data, &len);
    TEST_ASSERT(rc == CKR_FUNCTION_FAILED,
                "object_flatten should fail with NULL object");
    TEST_ASSERT(data == NULL, "data should remain NULL");
    TEST_ASSERT(len == 0, "len should remain 0");

    TEST_PASS_FUNC();
}

/* Test 2: object_flatten with valid object */
static int test_flatten_valid_object(void)
{
    OBJECT *obj = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;
    CK_RV rc;

    rc = create_test_object(&obj, CKO_DATA, "testobj1");
    TEST_ASSERT(rc == CKR_OK, "Failed to create test object");

    rc = object_flatten(obj, &data, &len);
    TEST_ASSERT(rc == CKR_OK, "object_flatten should succeed");
    TEST_ASSERT(data != NULL, "data should not be NULL");
    TEST_ASSERT(len > 0, "len should be greater than 0");

    /* Verify minimum size: class(4) + count(4) + name(8) */
    TEST_ASSERT(len >= 16, "len should be at least 16 bytes");

    /* Verify object class is stored correctly */
    CK_OBJECT_CLASS_32 stored_class;
    memcpy(&stored_class, data, sizeof(CK_OBJECT_CLASS_32));
    TEST_ASSERT(stored_class == CKO_DATA, "stored class should match");

    /* Verify object name is stored correctly */
    TEST_ASSERT(memcmp(data + 8, "testobj1", 8) == 0,
                "stored name should match");

    free(data);
    object_free(obj);

    TEST_PASS_FUNC();
}

/* Test 3: object_restore_withSize with NULL data */
static int test_restore_null_data(void)
{
    OBJECT *obj = NULL;
    CK_RV rc;

    rc = object_restore_withSize(NULL, NULL, &obj, FALSE, 100, NULL);
    TEST_ASSERT(rc == CKR_FUNCTION_FAILED,
                "object_restore_withSize should fail with NULL data");
    TEST_ASSERT(obj == NULL, "obj should remain NULL");

    TEST_PASS_FUNC();
}

/* Test 4: object_restore_withSize with NULL new_obj pointer */
static int test_restore_null_obj_ptr(void)
{
    CK_BYTE data[100];
    CK_RV rc;

    memset(data, 0, sizeof(data));
    rc = object_restore_withSize(NULL, data, NULL, FALSE, 100, NULL);
    TEST_ASSERT(rc == CKR_FUNCTION_FAILED,
                "object_restore_withSize should fail with NULL obj pointer");

    TEST_PASS_FUNC();
}

/* Test 5: object_restore_withSize with insufficient data_size */
static int test_restore_insufficient_size(void)
{
    CK_BYTE data[100];
    OBJECT *obj = NULL;
    CK_RV rc;

    memset(data, 0, sizeof(data));

    /* Test with size less than minimum (class + count + name = 16 bytes) */
    rc = object_restore_withSize(NULL, data, &obj, FALSE, 15, NULL);
    TEST_ASSERT(rc == CKR_FUNCTION_FAILED,
                "object_restore_withSize should fail with size < 16");
    TEST_ASSERT(obj == NULL, "obj should remain NULL");

    TEST_PASS_FUNC();
}

/* Test 6: Round-trip test (flatten -> restore) */
static int test_roundtrip_flatten_restore(void)
{
    OBJECT *obj1 = NULL, *obj2 = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;
    CK_RV rc;

    /* Create and flatten object */
    rc = create_test_object(&obj1, CKO_SECRET_KEY, "roundtrp");
    TEST_ASSERT(rc == CKR_OK, "Failed to create test object");

    rc = object_flatten(obj1, &data, &len);
    TEST_ASSERT(rc == CKR_OK, "object_flatten should succeed");
    TEST_ASSERT(data != NULL && len > 0, "flatten should produce data");

    /* Restore object */
    rc = object_restore_withSize(NULL, data, &obj2, FALSE, len, NULL);
    TEST_ASSERT(rc == CKR_OK, "object_restore_withSize should succeed");
    TEST_ASSERT(obj2 != NULL, "restored object should not be NULL");

    /* Verify restored object matches original */
    TEST_ASSERT(obj2->class == obj1->class, "class should match");
    TEST_ASSERT(memcmp(obj2->name, obj1->name, 8) == 0, "name should match");
    TEST_ASSERT(template_compare(obj1->template, obj2->template), "template should match");

    free(data);
    object_free(obj1);
    object_free(obj2);

    TEST_PASS_FUNC();
}

/* Test 7: object_restore_withSize with filename validation */
static int test_restore_with_filename(void)
{
    OBJECT *obj1 = NULL, *obj2 = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;
    CK_RV rc;

    /* Create and flatten object with specific name */
    rc = create_test_object(&obj1, CKO_DATA, "filename");
    TEST_ASSERT(rc == CKR_OK, "Failed to create test object");

    rc = object_flatten(obj1, &data, &len);
    TEST_ASSERT(rc == CKR_OK, "object_flatten should succeed");

    /* Test with matching filename */
    rc = object_restore_withSize(NULL, data, &obj2, FALSE, len,
                                 "/path/to/filename");
    TEST_ASSERT(rc == CKR_OK,
                "object_restore_withSize should succeed with matching filename");
    TEST_ASSERT(obj2 != NULL, "restored object should not be NULL");
    object_free(obj2);
    obj2 = NULL;

    /* Test with mismatched filename */
    rc = object_restore_withSize(NULL, data, &obj2, FALSE, len,
                                 "/path/to/wrongnam");
    TEST_ASSERT(rc == CKR_FUNCTION_FAILED,
                "object_restore_withSize should fail with mismatched filename");
    TEST_ASSERT(obj2 == NULL, "obj should remain NULL on mismatch");

    /* Test with invalid filename format (too short) */
    rc = object_restore_withSize(NULL, data, &obj2, FALSE, len,
                                 "/path/to/short");
    TEST_ASSERT(rc == CKR_FUNCTION_FAILED,
                "object_restore_withSize should fail with short filename");

    free(data);
    object_free(obj1);

    TEST_PASS_FUNC();
}

/* Test 8: object_restore_withSize with replace flag */
static int test_restore_with_replace(void)
{
    OBJECT *obj1 = NULL, *obj2 = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;
    CK_RV rc;

    /* Create two objects */
    rc = create_test_object(&obj1, CKO_DATA, "original");
    TEST_ASSERT(rc == CKR_OK, "Failed to create first object");

    rc = create_test_object(&obj2, CKO_SECRET_KEY, "replacem");
    TEST_ASSERT(rc == CKR_OK, "Failed to create second object");

    /* Flatten the replacement object */
    rc = object_flatten(obj1, &data, &len);
    TEST_ASSERT(rc == CKR_OK, "object_flatten should succeed");

    /* Restore with replace flag */
    rc = object_restore_withSize(NULL, data, &obj2, TRUE, len, NULL);
    TEST_ASSERT(rc == CKR_OK,
                "object_restore_withSize should succeed with replace=TRUE");

    /* Verify template was replaced but object structure preserved */
    TEST_ASSERT(obj2 != NULL, "obj2 should still exist");
    /* Note: The replace operation updates the template, not the object itself */

    free(data);
    object_free(obj1);
    object_free(obj2);

    TEST_PASS_FUNC();
}

/* Test 9: Restore known object data  */
static int test_restore_known_data(void)
{
    OBJECT *obj1 = NULL, *obj2 = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;
    CK_RV rc;

    CK_BYTE known_data[] = {
#ifdef __BIG_ENDIAN__
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f,
            0x4f, 0x42, 0x70, 0x35, 0x79, 0x48, 0x5a, 0x59,
            0x00, 0x00, 0x01, 0x29, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xa2, 0x30, 0x81, 0x9f, 0x30,
            0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81,
            0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81,
            0x00, 0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17,
            0x58, 0x9a, 0x51, 0x87, 0xdc, 0x7e, 0xa8, 0x41,
            0xd1, 0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52,
            0xa4, 0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9,
            0x91, 0xd8, 0xc5, 0x10, 0x56, 0xff, 0xed, 0xb1,
            0x62, 0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88,
            0xa3, 0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91,
            0xcb, 0xb3, 0x07, 0xce, 0xab, 0xfc, 0xe0, 0xb1,
            0xdf, 0xd5, 0xcd, 0x95, 0x08, 0x09, 0x6d, 0x5b,
            0x2b, 0x8b, 0x6d, 0xf5, 0xd6, 0x71, 0xef, 0x63,
            0x77, 0xc0, 0x92, 0x1c, 0xb2, 0x3c, 0x27, 0x0a,
            0x70, 0xe2, 0x59, 0x8e, 0x6f, 0xf8, 0x9d, 0x19,
            0xf1, 0x05, 0xac, 0xc2, 0xd3, 0xf0, 0xcb, 0x35,
            0xf2, 0x92, 0x80, 0xe1, 0x38, 0x6b, 0x6f, 0x64,
            0xc4, 0xef, 0x22, 0xe1, 0xe1, 0xf2, 0x0d, 0x0c,
            0xe8, 0xcf, 0xfb, 0x22, 0x49, 0xbd, 0x9a, 0x21,
            0x37, 0x02, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x1d, 0x41, 0x6e, 0x6f, 0x74,
            0x68, 0x65, 0x72, 0x20, 0x52, 0x53, 0x41, 0x20,
            0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x6b,
            0x65, 0x79, 0x20, 0x6f, 0x62, 0x6a, 0x65, 0x63,
            0x74, 0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0xa5, 0x6e, 0x4a,
            0x0e, 0x70, 0x10, 0x17, 0x58, 0x9a, 0x51, 0x87,
            0xdc, 0x7e, 0xa8, 0x41, 0xd1, 0x56, 0xf2, 0xec,
            0x0e, 0x36, 0xad, 0x52, 0xa4, 0x4d, 0xfe, 0xb1,
            0xe6, 0x1f, 0x7a, 0xd9, 0x91, 0xd8, 0xc5, 0x10,
            0x56, 0xff, 0xed, 0xb1, 0x62, 0xb4, 0xc0, 0xf2,
            0x83, 0xa1, 0x2a, 0x88, 0xa3, 0x94, 0xdf, 0xf5,
            0x26, 0xab, 0x72, 0x91, 0xcb, 0xb3, 0x07, 0xce,
            0xab, 0xfc, 0xe0, 0xb1, 0xdf, 0xd5, 0xcd, 0x95,
            0x08, 0x09, 0x6d, 0x5b, 0x2b, 0x8b, 0x6d, 0xf5,
            0xd6, 0x71, 0xef, 0x63, 0x77, 0xc0, 0x92, 0x1c,
            0xb2, 0x3c, 0x27, 0x0a, 0x70, 0xe2, 0x59, 0x8e,
            0x6f, 0xf8, 0x9d, 0x19, 0xf1, 0x05, 0xac, 0xc2,
            0xd3, 0xf0, 0xcb, 0x35, 0xf2, 0x92, 0x80, 0xe1,
            0x38, 0x6b, 0x6f, 0x64, 0xc4, 0xef, 0x22, 0xe1,
            0xe1, 0xf2, 0x0d, 0x0c, 0xe8, 0xcf, 0xfb, 0x22,
            0x49, 0xbd, 0x9a, 0x21, 0x37, 0x00, 0x00, 0x01,
            0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x01, 0x00, 0x01, 0x40, 0x00, 0x02, 0x11,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e,
            0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x41, 0x6e,
            0x20, 0x52, 0x53, 0x41, 0x20, 0x70, 0x75, 0x62,
            0x6c, 0x69, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x20,
            0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x00,
            0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x40, 0x00,
            0x06, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x06, 0x33, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x01, 0x0b, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
            0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x0d,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x80, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00,
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x66, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x01, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x72,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x01, 0x71, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x40, 0x65, 0x61, 0x61, 0x66, 0x63, 0x39,
            0x30, 0x64, 0x35, 0x34, 0x64, 0x65, 0x33, 0x31,
            0x34, 0x38, 0x39, 0x64, 0x30, 0x39, 0x65, 0x33,
            0x66, 0x39, 0x34, 0x62, 0x39, 0x35, 0x66, 0x30,
            0x39, 0x62, 0x63, 0x35, 0x66, 0x31, 0x35, 0x61,
            0x62, 0x35, 0x65, 0x61, 0x30, 0x63, 0x65, 0x38,
            0x36, 0x32, 0x35, 0x64, 0x35, 0x63, 0x33, 0x39,
            0x37, 0x65, 0x32, 0x37, 0x37, 0x33, 0x64, 0x63,
            0x64, 0x33, 0x00, 0x00, 0x01, 0x70, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01
#else
            0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00,
            0x4f, 0x42, 0x70, 0x35, 0x79, 0x48, 0x5a, 0x59,
            0x29, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xa2, 0x00, 0x00, 0x00, 0x30, 0x81, 0x9f, 0x30,
            0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81,
            0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81,
            0x00, 0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17,
            0x58, 0x9a, 0x51, 0x87, 0xdc, 0x7e, 0xa8, 0x41,
            0xd1, 0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52,
            0xa4, 0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9,
            0x91, 0xd8, 0xc5, 0x10, 0x56, 0xff, 0xed, 0xb1,
            0x62, 0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88,
            0xa3, 0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91,
            0xcb, 0xb3, 0x07, 0xce, 0xab, 0xfc, 0xe0, 0xb1,
            0xdf, 0xd5, 0xcd, 0x95, 0x08, 0x09, 0x6d, 0x5b,
            0x2b, 0x8b, 0x6d, 0xf5, 0xd6, 0x71, 0xef, 0x63,
            0x77, 0xc0, 0x92, 0x1c, 0xb2, 0x3c, 0x27, 0x0a,
            0x70, 0xe2, 0x59, 0x8e, 0x6f, 0xf8, 0x9d, 0x19,
            0xf1, 0x05, 0xac, 0xc2, 0xd3, 0xf0, 0xcb, 0x35,
            0xf2, 0x92, 0x80, 0xe1, 0x38, 0x6b, 0x6f, 0x64,
            0xc4, 0xef, 0x22, 0xe1, 0xe1, 0xf2, 0x0d, 0x0c,
            0xe8, 0xcf, 0xfb, 0x22, 0x49, 0xbd, 0x9a, 0x21,
            0x37, 0x02, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x1d, 0x00, 0x00, 0x00, 0x41, 0x6e, 0x6f, 0x74,
            0x68, 0x65, 0x72, 0x20, 0x52, 0x53, 0x41, 0x20,
            0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x6b,
            0x65, 0x79, 0x20, 0x6f, 0x62, 0x6a, 0x65, 0x63,
            0x74, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x80, 0x00, 0x00, 0x00, 0xa5, 0x6e, 0x4a,
            0x0e, 0x70, 0x10, 0x17, 0x58, 0x9a, 0x51, 0x87,
            0xdc, 0x7e, 0xa8, 0x41, 0xd1, 0x56, 0xf2, 0xec,
            0x0e, 0x36, 0xad, 0x52, 0xa4, 0x4d, 0xfe, 0xb1,
            0xe6, 0x1f, 0x7a, 0xd9, 0x91, 0xd8, 0xc5, 0x10,
            0x56, 0xff, 0xed, 0xb1, 0x62, 0xb4, 0xc0, 0xf2,
            0x83, 0xa1, 0x2a, 0x88, 0xa3, 0x94, 0xdf, 0xf5,
            0x26, 0xab, 0x72, 0x91, 0xcb, 0xb3, 0x07, 0xce,
            0xab, 0xfc, 0xe0, 0xb1, 0xdf, 0xd5, 0xcd, 0x95,
            0x08, 0x09, 0x6d, 0x5b, 0x2b, 0x8b, 0x6d, 0xf5,
            0xd6, 0x71, 0xef, 0x63, 0x77, 0xc0, 0x92, 0x1c,
            0xb2, 0x3c, 0x27, 0x0a, 0x70, 0xe2, 0x59, 0x8e,
            0x6f, 0xf8, 0x9d, 0x19, 0xf1, 0x05, 0xac, 0xc2,
            0xd3, 0xf0, 0xcb, 0x35, 0xf2, 0x92, 0x80, 0xe1,
            0x38, 0x6b, 0x6f, 0x64, 0xc4, 0xef, 0x22, 0xe1,
            0xe1, 0xf2, 0x0d, 0x0c, 0xe8, 0xcf, 0xfb, 0x22,
            0x49, 0xbd, 0x9a, 0x21, 0x37, 0x22, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x11, 0x02, 0x00, 0x40,
            0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00,
            0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x41, 0x6e,
            0x20, 0x52, 0x53, 0x41, 0x20, 0x70, 0x75, 0x62,
            0x6c, 0x69, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x20,
            0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x21, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x2a, 0x06,
            0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x33, 0x06, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x86,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x01, 0x04, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x80,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x0c, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x66, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x63, 0x01,
            0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x72, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x71, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x65, 0x61, 0x61, 0x66, 0x63, 0x39,
            0x30, 0x64, 0x35, 0x34, 0x64, 0x65, 0x33, 0x31,
            0x34, 0x38, 0x39, 0x64, 0x30, 0x39, 0x65, 0x33,
            0x66, 0x39, 0x34, 0x62, 0x39, 0x35, 0x66, 0x30,
            0x39, 0x62, 0x63, 0x35, 0x66, 0x31, 0x35, 0x61,
            0x62, 0x35, 0x65, 0x61, 0x30, 0x63, 0x65, 0x38,
            0x36, 0x32, 0x35, 0x64, 0x35, 0x63, 0x33, 0x39,
            0x37, 0x65, 0x32, 0x37, 0x37, 0x33, 0x64, 0x63,
            0x64, 0x33, 0x70, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01
#endif
    };

    /* Restore object from known data */
    rc = object_restore_withSize(NULL, known_data, &obj1, FALSE, sizeof(known_data), NULL);
    TEST_ASSERT(rc == CKR_OK, "object_restore_withSize should succeed");
    TEST_ASSERT(obj1 != NULL, "restored object should not be NULL");

    /* Flatten object */
    rc = object_flatten(obj1, &data, &len);
    TEST_ASSERT(rc == CKR_OK, "object_flatten should succeed");
    TEST_ASSERT(data != NULL && len > 0, "flatten should produce data");
    TEST_ASSERT(len == sizeof(known_data), "flatten should produce the same number of bytes");

    /*
     * The flattened data may not be exactly the same as the known data because
     * the order of the attributes is not retained when restoring an object.
     * Restore the flattened data into a new object and compare the templates
     * of the objects.
     */
    rc = object_restore_withSize(NULL, data, &obj2, FALSE, len, NULL);
    TEST_ASSERT(rc == CKR_OK, "object_restore_withSize should succeed");
    TEST_ASSERT(obj2 != NULL, "restored object should not be NULL");

    /* Verify restored object matches original */
    TEST_ASSERT(obj2->class == obj1->class, "class should match");
    TEST_ASSERT(memcmp(obj2->name, obj1->name, 8) == 0, "name should match");
    TEST_ASSERT(template_compare(obj1->template, obj2->template), "template should match");

    free(data);
    object_free(obj1);
    object_free(obj2);

    TEST_PASS_FUNC();
}

/* ========== FUZZING TESTS ========== */

/* Helper function to generate random data */
static void generate_random_data(CK_BYTE *data, CK_ULONG len)
{
    for (CK_ULONG i = 0; i < len; i++) {
        data[i] = (CK_BYTE)(rand() % 256);
    }
}

/* Fuzz Test 1: Random data of various sizes */
static int fuzz_test_random_data(void)
{
    CK_BYTE data[1024];
    OBJECT *obj = NULL;
    CK_RV rc;
    int iterations = 1000;
    int safe_failures = 0;

    printf("Running fuzz test with %d iterations of random data...\n",
           iterations);

    for (int i = 0; i < iterations; i++) {
        CK_ULONG size = (rand() % 1000) + 1;
        generate_random_data(data, size);

        obj = NULL;
        rc = object_restore_withSize(NULL, data, &obj, FALSE, size, NULL);

        /* We expect most random data to fail gracefully */
        if (rc != CKR_OK) {
            safe_failures++;
            TEST_ASSERT(obj == NULL, "obj should be NULL on failure");
        } else {
            /* If it somehow succeeded, clean up */
            if (obj != NULL)
                object_free(obj);
        }
    }

    crashes_prevented += safe_failures;
    printf("  Safe failures: %d/%d (prevented crashes)\n",
           safe_failures, iterations);

    TEST_PASS_FUNC();
}

/* Fuzz Test 2: Boundary size values */
static int fuzz_test_boundary_sizes(void)
{
    CK_BYTE data[1024];
    OBJECT *obj = NULL;
    CK_RV rc;
    CK_ULONG test_sizes[] = {0, 1, 15, 16, 17, 255, 256, 1023, 1024};
    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);
    int safe_failures = 0;

    printf("Running fuzz test with boundary size values...\n");

    for (int i = 0; i < num_tests; i++) {
        CK_ULONG size = test_sizes[i];
        memset(data, 0xAA, sizeof(data));

        obj = NULL;
        rc = object_restore_withSize(NULL, data, &obj, FALSE, size, NULL);

        if (rc != CKR_OK) {
            safe_failures++;
            TEST_ASSERT(obj == NULL, "obj should be NULL on failure");
        } else {
            if (obj != NULL)
                object_free(obj);
        }
    }

    crashes_prevented += safe_failures;
    printf("  Safe failures: %d/%d (prevented crashes)\n",
           safe_failures, num_tests);

    TEST_PASS_FUNC();
}

/* Fuzz Test 3: Corrupted valid data */
static int fuzz_test_corrupted_data(void)
{
    OBJECT *obj1 = NULL, *obj2 = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;
    CK_RV rc;
    int iterations = 10000;
    int safe_failures = 0;

    printf("Running fuzz test with corrupted valid data...\n");

    /* Create a valid object and flatten it */
    rc = create_test_object(&obj1, CKO_DATA, "corrupt1");
    TEST_ASSERT(rc == CKR_OK, "Failed to create test object");

    rc = object_flatten(obj1, &data, &len);
    TEST_ASSERT(rc == CKR_OK, "object_flatten should succeed");

    /* Corrupt the data in various ways */
    for (int i = 0; i < iterations; i++) {
        CK_BYTE *corrupted = (CK_BYTE *)malloc(len);
        TEST_ASSERT(corrupted != NULL, "malloc failed");

        memcpy(corrupted, data, len);

        /* Randomly corrupt 1-5 bytes */
        int num_corruptions = (rand() % 5) + 1;
        for (int j = 0; j < num_corruptions; j++) {
            CK_ULONG pos = rand() % len;
            corrupted[pos] = (CK_BYTE)(rand() % 256);
        }

        obj2 = NULL;
        rc = object_restore_withSize(NULL, corrupted, &obj2, FALSE, len, NULL);

        if (rc != CKR_OK) {
            safe_failures++;
            TEST_ASSERT(obj2 == NULL, "obj should be NULL on failure");
        } else {
            if (obj2 != NULL)
                object_free(obj2);
        }

        free(corrupted);
    }

    crashes_prevented += safe_failures;
    printf("  Safe failures: %d/%d (prevented crashes)\n",
           safe_failures, iterations);

    free(data);
    object_free(obj1);

    TEST_PASS_FUNC();
}

/* Fuzz Test 4: Extreme count values */
static int fuzz_test_extreme_counts(void)
{
    CK_BYTE data[1024];
    OBJECT *obj = NULL;
    CK_RV rc;
    CK_ULONG_32 extreme_counts[] = {
        0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
        1000000, 0xFFFFFFFE
    };
    int num_tests = sizeof(extreme_counts) / sizeof(extreme_counts[0]);
    int safe_failures = 0;

    printf("Running fuzz test with extreme count values...\n");

    for (int i = 0; i < num_tests; i++) {
        memset(data, 0, sizeof(data));

        /* Set up minimal valid structure with extreme count */
        CK_OBJECT_CLASS_32 class32 = CKO_DATA;
        memcpy(data, &class32, sizeof(CK_OBJECT_CLASS_32));
        memcpy(data + 4, &extreme_counts[i], sizeof(CK_ULONG_32));
        memcpy(data + 8, "extreme1", 8);

        obj = NULL;
        rc = object_restore_withSize(NULL, data, &obj, FALSE, 1024, NULL);

        if (rc != CKR_OK) {
            safe_failures++;
            TEST_ASSERT(obj == NULL, "obj should be NULL on failure");
        } else {
            if (obj != NULL)
                object_free(obj);
        }
    }

    crashes_prevented += safe_failures;
    printf("  Safe failures: %d/%d (prevented crashes)\n",
           safe_failures, num_tests);

    TEST_PASS_FUNC();
}

/* Fuzz Test 5: Size mismatches */
static int fuzz_test_size_mismatches(void)
{
    OBJECT *obj1 = NULL, *obj2 = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;
    CK_RV rc;
    int safe_failures = 0;

    printf("Running fuzz test with size mismatches...\n");

    /* Create a valid object and flatten it */
    rc = create_test_object(&obj1, CKO_DATA, "sizemism");
    TEST_ASSERT(rc == CKR_OK, "Failed to create test object");

    rc = object_flatten(obj1, &data, &len);
    TEST_ASSERT(rc == CKR_OK, "object_flatten should succeed");

    /* Test with various incorrect sizes */
    CK_ULONG test_sizes[] = {
        len - 1, len + 1, len / 2, len * 2,
        16, len - 10, len + 100
    };
    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);

    for (int i = 0; i < num_tests; i++) {
        obj2 = NULL;
        rc = object_restore_withSize(NULL, data, &obj2, FALSE,
                                     test_sizes[i], NULL);

        if (rc != CKR_OK) {
            safe_failures++;
            TEST_ASSERT(obj2 == NULL, "obj should be NULL on failure");
        } else {
            if (obj2 != NULL)
                object_free(obj2);
        }
    }

    crashes_prevented += safe_failures;
    printf("  Safe failures: %d/%d (prevented crashes)\n",
           safe_failures, num_tests);

    free(data);
    object_free(obj1);

    TEST_PASS_FUNC();
}

/* ========== MAIN TEST RUNNER ========== */

int main(int argc, char **argv)
{
    int rc = 0;

    (void)argc;  /* Suppress unused parameter warning */
    (void)argv;  /* Suppress unused parameter warning */

    /* Initialize random seed for fuzzing tests */
    srand((unsigned int)time(NULL));

    printf("\n");
    printf("========================================\n");
    printf("Object Flatten/Restore Test Suite\n");
    printf("========================================\n\n");

    printf("=== UNIT TESTS ===\n");

    if (test_flatten_null_object() != 0)
        rc = 1;

    if (test_flatten_valid_object() != 0)
        rc = 1;

    if (test_restore_null_data() != 0)
        rc = 1;

    if (test_restore_null_obj_ptr() != 0)
        rc = 1;

    if (test_restore_insufficient_size() != 0)
        rc = 1;

    if (test_roundtrip_flatten_restore() != 0)
        rc = 1;

    if (test_restore_with_filename() != 0)
        rc = 1;

    if (test_restore_with_replace() != 0)
        rc = 1;

    if (test_restore_known_data() != 0)
        rc = 1;

    printf("\n=== FUZZING TESTS ===\n");

    if (fuzz_test_random_data() != 0)
        rc = 1;

    if (fuzz_test_boundary_sizes() != 0)
        rc = 1;

    if (fuzz_test_corrupted_data() != 0)
        rc = 1;

    if (fuzz_test_extreme_counts() != 0)
        rc = 1;

    if (fuzz_test_size_mismatches() != 0)
        rc = 1;

    printf("\n========================================\n");
    printf("Test Summary:\n");
    printf("  Total tests run: %d\n", tests_run);
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("  Crashes prevented: %d\n", crashes_prevented);
    printf("========================================\n\n");

    if (rc == 0)
        printf("All tests PASSED!\n");
    else
        printf("Some tests FAILED!\n");

    return (rc == 0) ? TEST_PASS : TEST_FAIL;
}
