/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _PIN_PROMPT_H_
#define _PIN_PROMPT_H_

void pin_free(char **buf);

/**
 * Print a message and prompt for input on stdin (echo is disabled during
 * input).
 *
 * @param buf  Pointer to a string (char *) for buffering the input. It must
 *             be free-ed after usage.
 * @param msg  Pointer to the prompt message.
 * @returns    Pointer to the input on success, otherwise NULL. The returned
 *             pointer must not be free-ed.
 */
const char *pin_prompt(char **buf, const char *msg);

/**
 * Prompt for a new pin twice and compare both inputs.
 *
 * @param buf  Pointer to a string (char *) for buffering the input. It must
 *             be free-ed after usage.
 * @param msg1 Pointer to the first prompt message.
 * @param msg2 Pointer to the first prompt message.
 * @returns    Pointer to the pin on success (both inputs must be successful
 *             and both values must be equal), otherwise NULL. The returned
 *             pointer must not be free-ed.
 */
const char *pin_prompt_new(char **buf, const char *msg1, const char *msg2);

#endif /* _PIN_PROMPT_H_ */
