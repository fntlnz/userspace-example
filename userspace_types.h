#ifndef USERSPACE_TYPES_H
#define USERSPACE_TYPES_H

#include <stdint.h>

/* kernel type definitions that are missing in userspace */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef unsigned long long __u64;

#define ASSERT(X)

#endif // USERSPACE_TYPES_H
