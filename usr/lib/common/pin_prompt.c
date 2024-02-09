/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/crypto.h>

#include <pin_prompt.h>

static void echo(bool on)
{
    struct termios term;

    tcgetattr(fileno(stdin), &term);

    if (on)
        term.c_lflag |= ECHO;
    else
        term.c_lflag &= ~ECHO;

    tcsetattr(fileno(stdin), TCSAFLUSH, &term);
}

void pin_free(char **buf)
{
    if (!buf)
        return;

    if (*buf)
        OPENSSL_cleanse(*buf, strlen(*buf));

    free(*buf);
    *buf = NULL;
}

const char *pin_prompt(char **buf, const char *msg)
{
    ssize_t n;
    size_t s;

    if (!buf || *buf)
        return NULL;

    printf("%s", msg);
    fflush(stdout);
    echo(false);

    n = getline(buf, &s, stdin);

    echo(true);
    printf("\n");
    fflush(stdout);

    /* delayed getline() error handling */
    if (n == -1) {
        free(*buf);
        *buf = NULL;
        return NULL;
    }

    /* strip on first occurence of CR/LF */
    (*buf)[strcspn(*buf, "\r\n")] = '\0';

    return (const char *)*buf;
}

const char *pin_prompt_new(char **buf, const char *msg1, const char *msg2)
{
    const char *pin = NULL;
    char *buf2 = NULL;

    if (!pin_prompt(buf, msg1) ||
        !pin_prompt(&buf2, msg2))
        return NULL;

    if (strlen(*buf) && strlen(buf2) &&
       (!strcmp(*buf, buf2)))
        pin = *buf;

    pin_free(&buf2);

    return pin;
}
