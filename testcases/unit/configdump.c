#include "unittest.h"
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <cfgparser.h>
#include <configuration.h>
#include <err.h>

static const char test1[] = "foo = 1\nbar = 2\n";
static const char test2[] = "foo = 1 bar = 2\n";
static const char test3[] = "foo {\n  bar = 1\n  buzz = 2\n}\n";
static const char test4[] = "foo {\n  bar = 1 buzz = 2\n}\n";
static const char test5[] = "foo ( bar, buzz )\n";
static const char test6[] = "foo (\n      bar,\n      buzz\n    )\n";
static const char test7[] = "foo\n(\n  bar,\n  buzz\n)\n";
static const char nested1[] = "nested {\n  foo (\n        bar,\n        buzz\n      )\n}\n";
static const char nested2[] = "nested {\n  foo\n  (\n    bar,\n    buzz\n  )\n}\n";
static const char numpair1[] = "foo\n  1 2\n  3 4\nbar\n";
static char outbuf[1024];

static const char *curtest;

static FILE *opentest(const char *test)
{
    FILE *res = fmemopen((char *)test, strlen(test), "r");
    if (!res)
        err(TEST_FAIL, "Could not fmemopen test string \"%s\"", test);
    return res;
}

static FILE *openout(void)
{
    FILE *res = fmemopen(outbuf, sizeof(outbuf), "w");
    if (!res)
        err(TEST_FAIL, "Could not fmemopen output");
    return res;
}

static void parse_error(int line, int col, const char *msg)
{
    errx(TEST_FAIL, "Parsing \"%s\", line %d, col %d: %s\n",
         curtest, line, col, msg);
}

static void runparsedumptest(const char *test)
{
    struct ConfigBaseNode *config;
    FILE *in, *out;
    int ret;

    curtest = test;
    in = opentest(test);
    out = openout();
    ret = parse_configlib_file(in, &config, parse_error, 1);
    fclose(in);
    if (ret)
        errx(TEST_FAIL, "Failed to parse \"%s\"", test);
    confignode_dump(out, config, NULL, 2);
    fclose(out);
    confignode_deepfree(config);
    if (strcmp(test, outbuf))
        errx(TEST_FAIL, "Expected \"%s\", but got \"%s\"!", test, outbuf);
}

int main(void)
{
    runparsedumptest(test1);
    runparsedumptest(test2);
    runparsedumptest(test3);
    runparsedumptest(test4);
    runparsedumptest(test5);
    runparsedumptest(test6);
    runparsedumptest(test7);
    runparsedumptest(nested1);
    runparsedumptest(nested2);
    runparsedumptest(numpair1);
    return TEST_PASS;
}
