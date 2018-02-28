/* D:\Work\Custom\kodi-addons\heimdal\lib\wind\..\..\out\obj_AMD64\lib\wind/punycode_examples.h */
/* Automatically generated at 2018-02-22T11:18:27.324000 */

#ifndef PUNYCODE_EXAMPLES_H
#define PUNYCODE_EXAMPLES_H 1

#include <krb5-types.h>

#define MAX_LENGTH 40

struct punycode_example {
    size_t len;
    uint32_t val[MAX_LENGTH];
    const char *pc;
    const char *description;
};

extern const struct punycode_example punycode_examples[];

extern const size_t punycode_examples_size;
#endif /* PUNYCODE_EXAMPLES_H */
