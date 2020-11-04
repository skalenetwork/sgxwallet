/* src/libsecp256k1-config.h.  Generated from libsecp256k1-config.h.in by configure.  */
/* src/libsecp256k1-config.h.in.  Generated from configure.ac by autoheader.  */

#ifndef LIBSECP256K1_CONFIG_H

#define LIBSECP256K1_CONFIG_H

/* Define this symbol to compile out all VERIFY code */
/* #undef COVERAGE */

/* Set ecmult gen precision bits */
#define ECMULT_GEN_PREC_BITS 4

/* Set window size for ecmult precomputation */
#define ECMULT_WINDOW_SIZE 15

/* Define this symbol to enable the ECDH module */
/* #undef ENABLE_MODULE_ECDH */

/* Define this symbol to enable the extrakeys module */
/* #undef ENABLE_MODULE_EXTRAKEYS */

/* Define this symbol to enable the ECDSA pubkey recovery module */
/* #undef ENABLE_MODULE_RECOVERY */

/* Define this symbol to enable the schnorrsig module */
/* #undef ENABLE_MODULE_SCHNORRSIG */

/* Define this symbol if OpenSSL EC functions are available */
#define ENABLE_OPENSSL_TESTS 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define this symbol if libcrypto is installed */
#define HAVE_LIBCRYPTO 1

/* Define this symbol if libgmp is installed */
#define HAVE_LIBGMP 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"



/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define this symbol to enable x86_64 assembly optimizations */
#define USE_ASM_X86_64 1

/* Define this symbol to use a statically generated ecmult table */
#define USE_ECMULT_STATIC_PRECOMPUTATION 0

/* Define this symbol if an external (non-inline) assembly implementation is
   used */
/* #undef USE_EXTERNAL_ASM */

/* Define this symbol if an external implementation of the default callbacks
   is used */
/* #undef USE_EXTERNAL_DEFAULT_CALLBACKS */

/* Define this symbol to use the native field inverse implementation */
/* #undef USE_FIELD_INV_BUILTIN */

/* Define this symbol to use the num-based field inverse implementation */
#define USE_FIELD_INV_NUM 1

/* Define this symbol to force the use of the (unsigned) __int128 based wide
   multiplication implementation */
/* #undef USE_FORCE_WIDEMUL_INT128 */

/* Define this symbol to force the use of the (u)int64_t based wide
   multiplication implementation */
/* #undef USE_FORCE_WIDEMUL_INT64 */

/* Define this symbol to use the gmp implementation for num */
#define USE_NUM_GMP 1

/* Define this symbol to use no num implementation */
/* #undef USE_NUM_NONE */

/* Define this symbol to use the native scalar inverse implementation */
/* #undef USE_SCALAR_INV_BUILTIN */

/* Define this symbol to use the num-based scalar inverse implementation */
#define USE_SCALAR_INV_NUM 1


#endif /*LIBSECP256K1_CONFIG_H*/