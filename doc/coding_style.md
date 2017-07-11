# OpenCryptoki coding style

This document describes the preferred coding style for the OpenCryptoki project
and its related projects (openssl-ibmca and openssl-ibmpkcs11). Coding style is
always of personal taste, but defining one coding style makes the maintenance of
the project easier and gives a standard face for the source code, something that
this projects have been lacking for the past years.

The inspiration and formatting of this document came from the Linux Kernel
coding style document, but make no assumption as the coding style differ from
each other on some aspects.

## 1. Indentation

Tabs are 4 space characters, differently from many projects that define it as 8
characters. The main idea behind this is that 4 characters should give you a
clear idea about where a block of control starts and ends.

## 2. Line length

To keep the code readable and maintainable, the limit on the length of lines is
80 columns and this is a strongly preferred limit.

## 3. Placing Braces and Spaces

Here we follow Kernighan and Ritchie teachings. An opening brace is put last on
the line, and put the closing brace first, e.g.:

```
    if (x == 0) {
        do_y();
    }
```

This applies to all non-function statement blocks (if, switch, for, while, do).
Another example:

```
    switch (value) {
    case 1:
        return "one";
    case 2:
        return "two";
    case 3:
        return "three";
    default:
        return NULL;
    }
```

However, there is one special case, functions: their opening brace stays at the
beginning of the next line, e.g.:

```
    int func(int x)
    {
        do_something();
    }
```

Follow other examples:

```
    do {
        do_something();
    } while (condition);
```

```
    if (x == 1) {
        do_one();
    } else if (x > 1) {
        do_two();
    } else {
        do_three();
    }
```

It is not necessary to use braces when there is only a single statement, e.g.:

```
    if (x == 1)
        do_something();
```

and

```
    if (x == 1)
        do_something();
    else
        do_something_else();
```

This does not apply when only one branch in a conditional statement is a single
statement. In this, case use braces in all branches, e.g.:

```
    if (x == 1) {
        do_something();
        do_something_more();
    } else {
        do_something_else();
    }
```

### 3.1. Spaces

Always use a space after these keywords:
``` if, switch, case, for, do, while ```

E.g.:
```
    if (condition) {
        ..
    }
```

The following keywords should not have a space between them and their
parentheses:
``` sizeof, typeof ```

E.g.:
```
    s = sizeof(struct alg);
```

Do **not** add spaces around (inside) parenthesized expressions, e.g.:
```
    if ( x == 1 ) {
        ..
    }
```

When declaring a pointer or a function that returns a pointer type, the ``*``
must be put adjacent to the data name or function name, e.g.:
```
    int *ptr;
    void ptrcopy(int *dest, char *src);
    int *get_address(int *ptr);
```

Use one space on each side of the following operators:
``` =  +  -  <  >  *  / %  |  &  ^  <=  >=  ==  !=  ?  : ```

but no space after unary operators:
``` &  *  +  -  ~  !  ```

no space before postfix/after prefix increment and decrement operators:
``` ++ -- ```

and no space around the ``.`` and ``->`` structure member operators.

Do **not** leave trailing whitespace at the end of lines.

## 4. Naming

Avoid using CamelCase. It is preferred to name variables and functions by
including an underscore between words, e.g.:
```
    int person_counter;
```

## 5. Commenting

Comments in the code make everyone's life easier, but don't be too verbose.
Focus on **what** your function does and less on **how** it does.

The preferred style for long multi-line comments is:

```
    /*
     * This is a multi-line comment.
     *
     * A column of asterisks on the left side, with beginning and ending
     * almost-blank lines.
     */
```

