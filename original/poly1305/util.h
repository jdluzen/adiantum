#pragma once
/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "cipherbench.h"

#if defined(__linux__)
#include <linux/types.h>	/* for __le32 etc. */
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#undef SIMD_IMPL_NAME
#if defined(__arm__) || defined(__aarch64__)
#  define SIMD_IMPL_NAME "NEON"
#endif

#define forceinline inline __attribute__((always_inline))
#ifndef __always_inline
#  define __always_inline	forceinline
#endif
#define noinline __attribute__((noinline))

#define __cacheline_aligned __attribute__((aligned(64)))

#ifndef __noreturn
#  define __noreturn	__attribute__((noreturn))
#endif

#ifndef __cold
#  define __cold	__attribute__((cold))
#endif

#define ARRAY_SIZE(A)	(sizeof(A) / sizeof((A)[0]))

#define BUILD_BUG_ON(condition)	((void)sizeof(char[1 - 2*!!(condition)]))

#define asmlinkage

#define swap(a, b) \
        do { __typeof__(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define min(a, b) ({ __typeof__(a) _a = (a); \
		     __typeof__(b) _b = (b); \
		     _a < _b ? _a : _b; })

#define max(a, b) ({ __typeof__(a) _a = (a); \
		     __typeof__(b) _b = (b); \
		     _a > _b ? _a : _b; })

#define __round_mask(x, y)  ((__typeof__(x))((y)-1))
#define round_up(x, y)      ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y)    ((x) & ~__round_mask(x, y))

#ifdef __CHECKER__
#define __force		__attribute__((force))
#define __bitwise__	__attribute__((bitwise))
#else
#define __force
#define __bitwise__
#endif

#if !defined(__linux__)

typedef u32 __bitwise__ __le32;
typedef u64 __bitwise__ __le64;
typedef u32 __bitwise__ __be32;
typedef u64 __bitwise__ __be64;

#endif

#define cpu_to_le32(v)	((__force __le32)(u32)(v))
#define le32_to_cpu(v)	((__force u32)(__le32)(v))
#define cpu_to_le64(v)	((__force __le64)(u64)(v))
#define le64_to_cpu(v)	((__force u64)(__le64)(v))

#define __builtin_bswap64(v) _byteswap_ulong(v)
#define __builtin_bswap32(v) _byteswap_ushort(v)
#define cpu_to_be32(v)	((__force __be32)__builtin_bswap32(v))
#define be32_to_cpu(v)	(__builtin_bswap32((__force u32)v))
#define cpu_to_be64(v)	((__force __be64)__builtin_bswap64(v))
#define be64_to_cpu(v)	(__builtin_bswap64((__force u64)v))

struct ulong_unaligned { unsigned long v; };
struct le32_unaligned { __le32 v; };
struct be32_unaligned { __be32 v; };
struct le64_unaligned { __le64 v; };
struct be64_unaligned { __be64 v; };

static inline u32 get_unaligned_le32(const void* p)
{
	return le32_to_cpu(((const struct le32_unaligned*)p)->v);
}

static inline u32 get_unaligned_be32(const void* p)
{
	return be32_to_cpu(((const struct be32_unaligned*)p)->v);
}

static inline void put_unaligned_le32(u32 v, void* p)
{
	((struct le32_unaligned*)p)->v = cpu_to_le32(v);
}

static inline void put_unaligned_be32(u32 v, void* p)
{
	((struct be32_unaligned*)p)->v = cpu_to_be32(v);
}

static inline u64 get_unaligned_le64(const void* p)
{
	return le64_to_cpu(((const struct le64_unaligned*)p)->v);
}

static inline u64 get_unaligned_be64(const void* p)
{
	return be64_to_cpu(((const struct be64_unaligned*)p)->v);
}

static inline void put_unaligned_le64(u64 v, void* p)
{
	((struct le64_unaligned*)p)->v = cpu_to_le64(v);
}


static inline u16 rol16(u16 word, unsigned int shift)
{
	return (word << shift) | (word >> (16 - shift));
}

static inline u16 ror16(u16 word, unsigned int shift)
{
	return (word >> shift) | (word << (16 - shift));
}

static inline u32 rol32(u32 word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}

static inline u32 ror32(u32 word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

static inline u64 rol64(u64 word, unsigned int shift)
{
	return (word << shift) | (word >> (64 - shift));
}

static inline u64 ror64(u64 word, unsigned int shift)
{
	return (word >> shift) | (word << (64 - shift));
}


extern u64 cpu_frequency_kHz;

void show_result(const char* algname, const char* op, const char* impl,
	u64 nbytes, u64 ns_elapsed);

static inline u64 KB_per_s(u64 bytes, u64 ns_elapsed)
{
	return bytes * 1000000000 / ns_elapsed / 1000;
}

static inline float cycles_per_byte(u64 bytes, u64 ns_elapsed)
{
	return (double)((ns_elapsed * cpu_frequency_kHz) / bytes) / 1e6;
}

typedef struct {
	u64 lo, hi;
} ble128;

static inline void gf128mul_x_ble(ble128* x)
{
	u64 lo = x->lo;
	u64 hi = x->hi;

	x->lo = (lo << 1) ^ ((hi & (1ULL << 63)) ? 0x87 : 0);
	x->hi = (hi << 1) | (lo >> 63);
}

static inline void ble128_xor(ble128* dst, const ble128* src)
{
	dst->lo ^= src->lo;
	dst->hi ^= src->hi;
}

typedef union {
	struct {
		__le64 b;
		__le64 a;
	};
	__le32 w32[4];
} le128;

/* Addition in Z/(2^{128}Z) */
static inline void le128_add(le128* r, const le128* v1, const le128* v2)
{
	u64 x = le64_to_cpu(v1->b);
	u64 y = le64_to_cpu(v2->b);

	r->b = cpu_to_le64(x + y);
	r->a = cpu_to_le64(le64_to_cpu(v1->a) + le64_to_cpu(v2->a) +
		(x + y < x));
}

/* Subtraction in Z/(2^{128}Z) */
static inline void le128_sub(le128* r, const le128* v1, const le128* v2)
{
	u64 x = le64_to_cpu(v1->b);
	u64 y = le64_to_cpu(v2->b);

	r->b = cpu_to_le64(x - y);
	r->a = cpu_to_le64(le64_to_cpu(v1->a) - le64_to_cpu(v2->a) -
		(x - y > x));
}
