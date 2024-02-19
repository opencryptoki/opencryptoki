/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef GENERIC_AIX_BYTESWAP_H
#define GENERIC_AIX_BYTESWAP_H

#include <inttypes.h>
#include <sys/machine.h>

#ifndef bswap_16
# define bswap_16(x) \
        ((uint16_t)((((uint16_t) (x) & 0xff00) >> 8) |                  \
                    (((uint16_t) (x) & 0x00ff) << 8)))
#endif /* !bswap_16 */

#ifndef bswap_32
# define bswap_32(x) \
        ((uint32_t)((((uint32_t) (x) & 0xff000000) >> 24) |             \
                    (((uint32_t) (x) & 0x00ff0000) >> 8)  |             \
                    (((uint32_t) (x) & 0x0000ff00) << 8)  |             \
                    (((uint32_t) (x) & 0x000000ff) << 24)))
#endif /* !bswap_32 */

#ifndef bswap_64
# define bswap_64(x) \
        ((uint64_t)((((uint64_t) (x) & 0xff00000000000000ULL) >> 56) |  \
                    (((uint64_t) (x) & 0x00ff000000000000ULL) >> 40) |  \
                    (((uint64_t) (x) & 0x0000ff0000000000ULL) >> 24) |  \
                    (((uint64_t) (x) & 0x000000ff00000000ULL) >> 8)  |  \
                    (((uint64_t) (x) & 0x00000000ff000000ULL) << 8)  |  \
                    (((uint64_t) (x) & 0x0000000000ff0000ULL) << 24) |  \
                    (((uint64_t) (x) & 0x000000000000ff00ULL) << 40) |  \
                    (((uint64_t) (x) & 0x00000000000000ffULL) << 56)))
#endif /* !bswap_64 */

#endif /* GENERIC_AIX_BYTESWAP_H */

#ifndef GENERIC_AIX_ENDIAN_H
#define GENERIC_AIX_ENDIAN_H

#ifndef htobe16
# if __BIG_ENDIAN__

#  define htobe16(x) (x)
#  define htole16(x) bswap_16(x)
#  define be16toh(x) (x)
#  define le16toh(x) bswap_16(x)

# else /* __BIG_ENDIAN__ */

#  define htobe16(x) bswap_16(x)
#  define htole16(x) (x)
#  define be16toh(x) bswap_16(x)
#  define le16toh(x) (x)

# endif /* __BIG_ENDIAN__ */
#endif /* !htobe16 */

#ifndef htobe32
# if __BIG_ENDIAN__

#  define htobe32(x) (x)
#  define htole32(x) bswap_32(x)
#  define be32toh(x) (x)
#  define le32toh(x) bswap_32(x)

# else /* __BIG_ENDIAN__ */

#  define htobe32(x) bswap_32(x)
#  define htole32(x) (x)
#  define be32toh(x) bswap_32(x)
#  define le32toh(x) (x)

# endif /* __BIG_ENDIAN__ */
#endif /* !htobe32 */

#ifndef htobe64
# if __BIG_ENDIAN__

#  define htobe64(x) (x)
#  define htole64(x) bswap_64(x)
#  define be64toh(x) (x)
#  define le64toh(x) bswap_64(x)

#else /* __BIG_ENDIAN__ */

#  define htobe64(x) bswap_64(x)
#  define htole64(x) (x)
#  define be64toh(x) bswap_64(x)
#  define le64toh(x) (x)

# endif /* __BIG_ENDIAN__ */
#endif /* !htobe64 */
#endif /* GENERIC_AIX_ENDIAN_H */
