# 1 "secure_enclave.c"
# 1 "/home/kladko/sgxwallet/secure_enclave//"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "secure_enclave.c"
# 34 "secure_enclave.c"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/ecdsa.h" 1
# 10 "../intel-sgx-ssl/Linux/package/include/openssl/ecdsa.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h" 1
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h" 1
# 13 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/opensslv.h" 1
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h" 2
# 15 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h" 2


# 1 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h" 1
# 13 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/time.h" 1
# 44 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/time.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/cdefs.h" 1
# 45 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/time.h" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/_types.h" 1
# 39 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/_types.h"
typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef short __int16_t;
typedef unsigned short __uint16_t;
typedef int __int32_t;
typedef unsigned int __uint32_t;

typedef long __int64_t;
typedef unsigned long __uint64_t;






typedef __int8_t __int_least8_t;
typedef __uint8_t __uint_least8_t;
typedef __int16_t __int_least16_t;
typedef __uint16_t __uint_least16_t;
typedef __int32_t __int_least32_t;
typedef __uint32_t __uint_least32_t;
typedef __int64_t __int_least64_t;
typedef __uint64_t __uint_least64_t;


typedef __int8_t __int_fast8_t;
typedef __uint8_t __uint_fast8_t;


typedef long int __int_fast16_t;
typedef unsigned long int __uint_fast16_t;
typedef long int __int_fast32_t;
typedef unsigned long int __uint_fast32_t;
typedef long int __int_fast64_t;
typedef unsigned long int __uint_fast64_t;
# 84 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/_types.h"
typedef long __off_t;
# 97 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/_types.h"
typedef __int64_t __intptr_t;
typedef __uint64_t __uintptr_t;
typedef __int64_t __ptrdiff_t;


typedef unsigned long __size_t;
typedef long __ssize_t;
typedef double __double_t;
typedef float __float_t;



typedef long __clock_t;

typedef long __time_t;
typedef __builtin_va_list __va_list;
typedef unsigned int __wint_t;

typedef unsigned long int __wctype_t;
typedef int * __wctrans_t;






typedef struct {
    int __c;
    union {
        __wint_t __wc;
        char __wcb[4];
    } __v;
} __mbstate_t;


typedef __int64_t __intmax_t;
typedef __uint64_t __uintmax_t;
# 46 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/time.h" 2
# 58 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/time.h"
typedef __clock_t clock_t;





typedef __time_t time_t;





typedef __size_t size_t;




struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;

    long tm_gmtoff;
    char *tm_zone;
};




double difftime(time_t, time_t);
char * asctime(const struct tm *);
size_t strftime(char *, size_t, const char *, const struct tm *);




char * asctime_r(const struct tm *, char *);


# 14 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h" 2
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/e_os2.h" 1
# 13 "../intel-sgx-ssl/Linux/package/include/openssl/e_os2.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h" 1
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/e_os2.h" 2
# 243 "../intel-sgx-ssl/Linux/package/include/openssl/e_os2.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/inttypes.h" 1
# 22 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/inttypes.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/stdint.h" 1
# 28 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/stdint.h"
typedef __int8_t int8_t;




typedef __uint8_t uint8_t;




typedef __int16_t int16_t;




typedef __uint16_t uint16_t;




typedef __int32_t int32_t;




typedef __uint32_t uint32_t;




typedef __int64_t int64_t;




typedef __uint64_t uint64_t;



typedef __int_least8_t int_least8_t;
typedef __uint_least8_t uint_least8_t;
typedef __int_least16_t int_least16_t;
typedef __uint_least16_t uint_least16_t;
typedef __int_least32_t int_least32_t;
typedef __uint_least32_t uint_least32_t;
typedef __int_least64_t int_least64_t;
typedef __uint_least64_t uint_least64_t;


typedef __int_fast8_t int_fast8_t;
typedef __uint_fast8_t uint_fast8_t;
typedef __int_fast16_t int_fast16_t;
typedef __uint_fast16_t uint_fast16_t;
typedef __int_fast32_t int_fast32_t;
typedef __uint_fast32_t uint_fast32_t;
typedef __int_fast64_t int_fast64_t;
typedef __uint_fast64_t uint_fast64_t;




typedef __intptr_t intptr_t;




typedef __uintptr_t uintptr_t;



typedef __intmax_t intmax_t;
typedef __uintmax_t uintmax_t;
# 23 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/inttypes.h" 2
# 316 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/inttypes.h"
typedef struct {
    intmax_t quot;
    intmax_t rem;
} imaxdiv_t;



intmax_t imaxabs(intmax_t);
imaxdiv_t imaxdiv(intmax_t, intmax_t);
intmax_t strtoimax(const char *, char **, int);
uintmax_t strtoumax(const char *, char **, int);


# 244 "../intel-sgx-ssl/Linux/package/include/openssl/e_os2.h" 2
# 15 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h" 2
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h" 1
# 16 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h" 2
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h" 1
# 18 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdarg.h" 1
# 41 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdarg.h"
typedef __va_list va_list;
# 19 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h" 2

# 1 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h" 1
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdlib.h" 1
# 51 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdlib.h"
typedef int wchar_t;



typedef struct {
    int quot;
    int rem;
} div_t;

typedef struct {
    long quot;
    long rem;
} ldiv_t;

typedef struct {
    long long quot;
    long long rem;
} lldiv_t;
# 86 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdlib.h"


__attribute__ ((__noreturn__)) void abort(void);
int atexit(void (*)(void));
int abs(int);
double atof(const char *);
int atoi(const char *);
long atol(const char *);
void * bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));
void * calloc(size_t, size_t);
div_t div(int, int);
void free(void *);
long labs(long);
ldiv_t ldiv(long, long);
void * malloc(size_t);
void * memalign(size_t, size_t);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
void * realloc(void *, size_t);
double strtod(const char *, char **);
long strtol(const char *, char **, int);
float strtof(const char *, char **);

long long
        atoll(const char *);
long long
        llabs(long long);
lldiv_t
        lldiv(long long, long long);
long long
        strtoll(const char *, char **, int);
unsigned long
        strtoul(const char *, char **, int);
long double
        strtold(const char *, char **);
unsigned long long
        strtoull(const char *, char **, int);

int mblen(const char *, size_t);
size_t mbstowcs(wchar_t *, const char *, size_t);
int wctomb(char *, wchar_t);
int mbtowc(wchar_t *, const char *, size_t);
size_t wcstombs(char *, const wchar_t *, size_t);





;
;
;
;
;
;
;




void * alloca(size_t);







# 15 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h" 2
# 23 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/safestack.h" 1
# 13 "../intel-sgx-ssl/Linux/package/include/openssl/safestack.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/stack.h" 1
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/stack.h"
typedef struct stack_st OPENSSL_STACK;

typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);
typedef void (*OPENSSL_sk_freefunc)(void *);
typedef void *(*OPENSSL_sk_copyfunc)(const void *);

int OPENSSL_sk_num(const OPENSSL_STACK *);
void *OPENSSL_sk_value(const OPENSSL_STACK *, int);

void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data);

OPENSSL_STACK *OPENSSL_sk_new(OPENSSL_sk_compfunc cmp);
OPENSSL_STACK *OPENSSL_sk_new_null(void);
OPENSSL_STACK *OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc c, int n);
int OPENSSL_sk_reserve(OPENSSL_STACK *st, int n);
void OPENSSL_sk_free(OPENSSL_STACK *);
void OPENSSL_sk_pop_free(OPENSSL_STACK *st, void (*func) (void *));
OPENSSL_STACK *OPENSSL_sk_deep_copy(const OPENSSL_STACK *,
                                    OPENSSL_sk_copyfunc c,
                                    OPENSSL_sk_freefunc f);
int OPENSSL_sk_insert(OPENSSL_STACK *sk, const void *data, int where);
void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc);
void *OPENSSL_sk_delete_ptr(OPENSSL_STACK *st, const void *p);
int OPENSSL_sk_find(OPENSSL_STACK *st, const void *data);
int OPENSSL_sk_find_ex(OPENSSL_STACK *st, const void *data);
int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
int OPENSSL_sk_unshift(OPENSSL_STACK *st, const void *data);
void *OPENSSL_sk_shift(OPENSSL_STACK *st);
void *OPENSSL_sk_pop(OPENSSL_STACK *st);
void OPENSSL_sk_zero(OPENSSL_STACK *st);
OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK *sk,
                                            OPENSSL_sk_compfunc cmp);
OPENSSL_STACK *OPENSSL_sk_dup(const OPENSSL_STACK *st);
void OPENSSL_sk_sort(OPENSSL_STACK *st);
int OPENSSL_sk_is_sorted(const OPENSSL_STACK *st);
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/safestack.h" 2
# 149 "../intel-sgx-ssl/Linux/package/include/openssl/safestack.h"
typedef char *OPENSSL_STRING;
typedef const char *OPENSSL_CSTRING;
# 159 "../intel-sgx-ssl/Linux/package/include/openssl/safestack.h"
struct stack_st_OPENSSL_STRING; typedef int (*sk_OPENSSL_STRING_compfunc)(const char * const *a, const char *const *b); typedef void (*sk_OPENSSL_STRING_freefunc)(char *a); typedef char * (*sk_OPENSSL_STRING_copyfunc)(const char *a); static __attribute__((unused)) inline int sk_OPENSSL_STRING_num(const struct stack_st_OPENSSL_STRING *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline char *sk_OPENSSL_STRING_value(const struct stack_st_OPENSSL_STRING *sk, int idx) { return (char *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_OPENSSL_STRING *sk_OPENSSL_STRING_new(sk_OPENSSL_STRING_compfunc compare) { return (struct stack_st_OPENSSL_STRING *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_OPENSSL_STRING *sk_OPENSSL_STRING_new_null(void) { return (struct stack_st_OPENSSL_STRING *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_OPENSSL_STRING *sk_OPENSSL_STRING_new_reserve(sk_OPENSSL_STRING_compfunc compare, int n) { return (struct stack_st_OPENSSL_STRING *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_OPENSSL_STRING_reserve(struct stack_st_OPENSSL_STRING *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_OPENSSL_STRING_free(struct stack_st_OPENSSL_STRING *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_OPENSSL_STRING_zero(struct stack_st_OPENSSL_STRING *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline char *sk_OPENSSL_STRING_delete(struct stack_st_OPENSSL_STRING *sk, int i) { return (char *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline char *sk_OPENSSL_STRING_delete_ptr(struct stack_st_OPENSSL_STRING *sk, char *ptr) { return (char *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_STRING_push(struct stack_st_OPENSSL_STRING *sk, char *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_STRING_unshift(struct stack_st_OPENSSL_STRING *sk, char *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline char *sk_OPENSSL_STRING_pop(struct stack_st_OPENSSL_STRING *sk) { return (char *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline char *sk_OPENSSL_STRING_shift(struct stack_st_OPENSSL_STRING *sk) { return (char *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_OPENSSL_STRING_pop_free(struct stack_st_OPENSSL_STRING *sk, sk_OPENSSL_STRING_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_OPENSSL_STRING_insert(struct stack_st_OPENSSL_STRING *sk, char *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline char *sk_OPENSSL_STRING_set(struct stack_st_OPENSSL_STRING *sk, int idx, char *ptr) { return (char *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_STRING_find(struct stack_st_OPENSSL_STRING *sk, char *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_STRING_find_ex(struct stack_st_OPENSSL_STRING *sk, char *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_OPENSSL_STRING_sort(struct stack_st_OPENSSL_STRING *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_OPENSSL_STRING_is_sorted(const struct stack_st_OPENSSL_STRING *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_OPENSSL_STRING * sk_OPENSSL_STRING_dup(const struct stack_st_OPENSSL_STRING *sk) { return (struct stack_st_OPENSSL_STRING *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_OPENSSL_STRING *sk_OPENSSL_STRING_deep_copy(const struct stack_st_OPENSSL_STRING *sk, sk_OPENSSL_STRING_copyfunc copyfunc, sk_OPENSSL_STRING_freefunc freefunc) { return (struct stack_st_OPENSSL_STRING *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_OPENSSL_STRING_compfunc sk_OPENSSL_STRING_set_cmp_func(struct stack_st_OPENSSL_STRING *sk, sk_OPENSSL_STRING_compfunc compare) { return (sk_OPENSSL_STRING_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }
struct stack_st_OPENSSL_CSTRING; typedef int (*sk_OPENSSL_CSTRING_compfunc)(const char * const *a, const char *const *b); typedef void (*sk_OPENSSL_CSTRING_freefunc)(char *a); typedef char * (*sk_OPENSSL_CSTRING_copyfunc)(const char *a); static __attribute__((unused)) inline int sk_OPENSSL_CSTRING_num(const struct stack_st_OPENSSL_CSTRING *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline const char *sk_OPENSSL_CSTRING_value(const struct stack_st_OPENSSL_CSTRING *sk, int idx) { return (const char *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_OPENSSL_CSTRING *sk_OPENSSL_CSTRING_new(sk_OPENSSL_CSTRING_compfunc compare) { return (struct stack_st_OPENSSL_CSTRING *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_OPENSSL_CSTRING *sk_OPENSSL_CSTRING_new_null(void) { return (struct stack_st_OPENSSL_CSTRING *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_OPENSSL_CSTRING *sk_OPENSSL_CSTRING_new_reserve(sk_OPENSSL_CSTRING_compfunc compare, int n) { return (struct stack_st_OPENSSL_CSTRING *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_OPENSSL_CSTRING_reserve(struct stack_st_OPENSSL_CSTRING *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_OPENSSL_CSTRING_free(struct stack_st_OPENSSL_CSTRING *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_OPENSSL_CSTRING_zero(struct stack_st_OPENSSL_CSTRING *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline const char *sk_OPENSSL_CSTRING_delete(struct stack_st_OPENSSL_CSTRING *sk, int i) { return (const char *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline const char *sk_OPENSSL_CSTRING_delete_ptr(struct stack_st_OPENSSL_CSTRING *sk, const char *ptr) { return (const char *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_CSTRING_push(struct stack_st_OPENSSL_CSTRING *sk, const char *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_CSTRING_unshift(struct stack_st_OPENSSL_CSTRING *sk, const char *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline const char *sk_OPENSSL_CSTRING_pop(struct stack_st_OPENSSL_CSTRING *sk) { return (const char *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline const char *sk_OPENSSL_CSTRING_shift(struct stack_st_OPENSSL_CSTRING *sk) { return (const char *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_OPENSSL_CSTRING_pop_free(struct stack_st_OPENSSL_CSTRING *sk, sk_OPENSSL_CSTRING_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_OPENSSL_CSTRING_insert(struct stack_st_OPENSSL_CSTRING *sk, const char *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline const char *sk_OPENSSL_CSTRING_set(struct stack_st_OPENSSL_CSTRING *sk, int idx, const char *ptr) { return (const char *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_CSTRING_find(struct stack_st_OPENSSL_CSTRING *sk, const char *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_CSTRING_find_ex(struct stack_st_OPENSSL_CSTRING *sk, const char *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_OPENSSL_CSTRING_sort(struct stack_st_OPENSSL_CSTRING *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_OPENSSL_CSTRING_is_sorted(const struct stack_st_OPENSSL_CSTRING *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_OPENSSL_CSTRING * sk_OPENSSL_CSTRING_dup(const struct stack_st_OPENSSL_CSTRING *sk) { return (struct stack_st_OPENSSL_CSTRING *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_OPENSSL_CSTRING *sk_OPENSSL_CSTRING_deep_copy(const struct stack_st_OPENSSL_CSTRING *sk, sk_OPENSSL_CSTRING_copyfunc copyfunc, sk_OPENSSL_CSTRING_freefunc freefunc) { return (struct stack_st_OPENSSL_CSTRING *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_OPENSSL_CSTRING_compfunc sk_OPENSSL_CSTRING_set_cmp_func(struct stack_st_OPENSSL_CSTRING *sk, sk_OPENSSL_CSTRING_compfunc compare) { return (sk_OPENSSL_CSTRING_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }





typedef void *OPENSSL_BLOCK;
struct stack_st_OPENSSL_BLOCK; typedef int (*sk_OPENSSL_BLOCK_compfunc)(const void * const *a, const void *const *b); typedef void (*sk_OPENSSL_BLOCK_freefunc)(void *a); typedef void * (*sk_OPENSSL_BLOCK_copyfunc)(const void *a); static __attribute__((unused)) inline int sk_OPENSSL_BLOCK_num(const struct stack_st_OPENSSL_BLOCK *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void *sk_OPENSSL_BLOCK_value(const struct stack_st_OPENSSL_BLOCK *sk, int idx) { return (void *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_OPENSSL_BLOCK *sk_OPENSSL_BLOCK_new(sk_OPENSSL_BLOCK_compfunc compare) { return (struct stack_st_OPENSSL_BLOCK *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_OPENSSL_BLOCK *sk_OPENSSL_BLOCK_new_null(void) { return (struct stack_st_OPENSSL_BLOCK *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_OPENSSL_BLOCK *sk_OPENSSL_BLOCK_new_reserve(sk_OPENSSL_BLOCK_compfunc compare, int n) { return (struct stack_st_OPENSSL_BLOCK *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_OPENSSL_BLOCK_reserve(struct stack_st_OPENSSL_BLOCK *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_OPENSSL_BLOCK_free(struct stack_st_OPENSSL_BLOCK *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_OPENSSL_BLOCK_zero(struct stack_st_OPENSSL_BLOCK *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void *sk_OPENSSL_BLOCK_delete(struct stack_st_OPENSSL_BLOCK *sk, int i) { return (void *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline void *sk_OPENSSL_BLOCK_delete_ptr(struct stack_st_OPENSSL_BLOCK *sk, void *ptr) { return (void *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_BLOCK_push(struct stack_st_OPENSSL_BLOCK *sk, void *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_BLOCK_unshift(struct stack_st_OPENSSL_BLOCK *sk, void *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void *sk_OPENSSL_BLOCK_pop(struct stack_st_OPENSSL_BLOCK *sk) { return (void *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void *sk_OPENSSL_BLOCK_shift(struct stack_st_OPENSSL_BLOCK *sk) { return (void *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_OPENSSL_BLOCK_pop_free(struct stack_st_OPENSSL_BLOCK *sk, sk_OPENSSL_BLOCK_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_OPENSSL_BLOCK_insert(struct stack_st_OPENSSL_BLOCK *sk, void *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline void *sk_OPENSSL_BLOCK_set(struct stack_st_OPENSSL_BLOCK *sk, int idx, void *ptr) { return (void *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_BLOCK_find(struct stack_st_OPENSSL_BLOCK *sk, void *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_OPENSSL_BLOCK_find_ex(struct stack_st_OPENSSL_BLOCK *sk, void *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_OPENSSL_BLOCK_sort(struct stack_st_OPENSSL_BLOCK *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_OPENSSL_BLOCK_is_sorted(const struct stack_st_OPENSSL_BLOCK *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_OPENSSL_BLOCK * sk_OPENSSL_BLOCK_dup(const struct stack_st_OPENSSL_BLOCK *sk) { return (struct stack_st_OPENSSL_BLOCK *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_OPENSSL_BLOCK *sk_OPENSSL_BLOCK_deep_copy(const struct stack_st_OPENSSL_BLOCK *sk, sk_OPENSSL_BLOCK_copyfunc copyfunc, sk_OPENSSL_BLOCK_freefunc freefunc) { return (struct stack_st_OPENSSL_BLOCK *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_OPENSSL_BLOCK_compfunc sk_OPENSSL_BLOCK_set_cmp_func(struct stack_st_OPENSSL_BLOCK *sk, sk_OPENSSL_BLOCK_compfunc compare) { return (sk_OPENSSL_BLOCK_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }
# 24 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h" 2

# 1 "../intel-sgx-ssl/Linux/package/include/openssl/ossl_typ.h" 1
# 13 "../intel-sgx-ssl/Linux/package/include/openssl/ossl_typ.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/limits.h" 1
# 39 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/limits.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/limits.h" 1
# 40 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/limits.h" 2
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/ossl_typ.h" 2
# 40 "../intel-sgx-ssl/Linux/package/include/openssl/ossl_typ.h"
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;


typedef struct asn1_object_st ASN1_OBJECT;

typedef struct ASN1_ITEM_st ASN1_ITEM;
typedef struct asn1_pctx_st ASN1_PCTX;
typedef struct asn1_sctx_st ASN1_SCTX;
# 78 "../intel-sgx-ssl/Linux/package/include/openssl/ossl_typ.h"
struct dane_st;
typedef struct bio_st BIO;
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;

typedef struct buf_mem_st BUF_MEM;

typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_st EVP_PKEY;

typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;

typedef struct hmac_ctx_st HMAC_CTX;

typedef struct dh_st DH;
typedef struct dh_method DH_METHOD;

typedef struct dsa_st DSA;
typedef struct dsa_method DSA_METHOD;

typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;

typedef struct ec_key_st EC_KEY;
typedef struct ec_key_method_st EC_KEY_METHOD;

typedef struct rand_meth_st RAND_METHOD;
typedef struct rand_drbg_st RAND_DRBG;

typedef struct ssl_dane_st SSL_DANE;
typedef struct x509_st X509;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_crl_st X509_CRL;
typedef struct x509_crl_method_st X509_CRL_METHOD;
typedef struct x509_revoked_st X509_REVOKED;
typedef struct X509_name_st X509_NAME;
typedef struct X509_pubkey_st X509_PUBKEY;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;

typedef struct x509_object_st X509_OBJECT;
typedef struct x509_lookup_st X509_LOOKUP;
typedef struct x509_lookup_method_st X509_LOOKUP_METHOD;
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;

typedef struct x509_sig_info_st X509_SIG_INFO;

typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;

typedef struct v3_ext_ctx X509V3_CTX;
typedef struct conf_st CONF;
typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;

typedef struct ui_st UI;
typedef struct ui_method_st UI_METHOD;

typedef struct engine_st ENGINE;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

typedef struct comp_ctx_st COMP_CTX;
typedef struct comp_method_st COMP_METHOD;

typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
typedef struct DIST_POINT_st DIST_POINT;
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

typedef struct ocsp_req_ctx_st OCSP_REQ_CTX;
typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ocsp_responder_id_st OCSP_RESPID;

typedef struct sct_st SCT;
typedef struct sct_ctx_st SCT_CTX;
typedef struct ctlog_st CTLOG;
typedef struct ctlog_store_st CTLOG_STORE;
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;

typedef struct ossl_store_info_st OSSL_STORE_INFO;
typedef struct ossl_store_search_st OSSL_STORE_SEARCH;



typedef intmax_t ossl_intmax_t;
typedef uintmax_t ossl_uintmax_t;
# 26 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h" 2
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h" 1
# 27 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h" 2
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/cryptoerr.h" 1
# 18 "../intel-sgx-ssl/Linux/package/include/openssl/cryptoerr.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/symhacks.h" 1
# 19 "../intel-sgx-ssl/Linux/package/include/openssl/cryptoerr.h" 2

int ERR_load_CRYPTO_strings(void);
# 28 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h" 2
# 61 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
typedef struct {
    int dummy;
} CRYPTO_dynlock;



typedef void CRYPTO_RWLOCK;

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void);
int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock);
int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock);
int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock);
void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock);

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock);
# 86 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
struct crypto_ex_data_st {
    struct stack_st_void *sk;
};
struct stack_st_void; typedef int (*sk_void_compfunc)(const void * const *a, const void *const *b); typedef void (*sk_void_freefunc)(void *a); typedef void * (*sk_void_copyfunc)(const void *a); static __attribute__((unused)) inline int sk_void_num(const struct stack_st_void *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void *sk_void_value(const struct stack_st_void *sk, int idx) { return (void *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_void *sk_void_new(sk_void_compfunc compare) { return (struct stack_st_void *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_void *sk_void_new_null(void) { return (struct stack_st_void *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_void *sk_void_new_reserve(sk_void_compfunc compare, int n) { return (struct stack_st_void *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_void_reserve(struct stack_st_void *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_void_free(struct stack_st_void *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_void_zero(struct stack_st_void *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void *sk_void_delete(struct stack_st_void *sk, int i) { return (void *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline void *sk_void_delete_ptr(struct stack_st_void *sk, void *ptr) { return (void *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_void_push(struct stack_st_void *sk, void *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_void_unshift(struct stack_st_void *sk, void *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void *sk_void_pop(struct stack_st_void *sk) { return (void *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void *sk_void_shift(struct stack_st_void *sk) { return (void *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_void_pop_free(struct stack_st_void *sk, sk_void_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_void_insert(struct stack_st_void *sk, void *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline void *sk_void_set(struct stack_st_void *sk, int idx, void *ptr) { return (void *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_void_find(struct stack_st_void *sk, void *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_void_find_ex(struct stack_st_void *sk, void *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_void_sort(struct stack_st_void *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_void_is_sorted(const struct stack_st_void *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_void * sk_void_dup(const struct stack_st_void *sk) { return (struct stack_st_void *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_void *sk_void_deep_copy(const struct stack_st_void *sk, sk_void_copyfunc copyfunc, sk_void_freefunc freefunc) { return (struct stack_st_void *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_void_compfunc sk_void_set_cmp_func(struct stack_st_void *sk, sk_void_compfunc compare) { return (sk_void_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }
# 115 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
int CRYPTO_mem_ctrl(int mode);
# 146 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
size_t OPENSSL_strlcpy(char *dst, const char *src, size_t siz);
size_t OPENSSL_strlcat(char *dst, const char *src, size_t siz);
size_t OPENSSL_strnlen(const char *str, size_t maxlen);
char *OPENSSL_buf2hexstr(const unsigned char *buffer, long len);
unsigned char *OPENSSL_hexstr2buf(const char *str, long *len);
int OPENSSL_hexchar2int(unsigned char c);



unsigned long OpenSSL_version_num(void);
const char *OpenSSL_version(int type);







int OPENSSL_issetugid(void);

typedef void CRYPTO_EX_new (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp);
typedef void CRYPTO_EX_free (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
                           void *from_d, int idx, long argl, void *argp);
 int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func);

int CRYPTO_free_ex_index(int class_index, int idx);





int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
                       const CRYPTO_EX_DATA *from);

void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);





int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx);
# 229 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
typedef struct crypto_threadid_st {
    int dummy;
} CRYPTO_THREADID;
# 256 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
int CRYPTO_set_mem_functions(
        void *(*m) (size_t, const char *, int),
        void *(*r) (void *, size_t, const char *, int),
        void (*f) (void *, const char *, int));
int CRYPTO_set_mem_debug(int flag);
void CRYPTO_get_mem_functions(
        void *(**m) (size_t, const char *, int),
        void *(**r) (void *, size_t, const char *, int),
        void (**f) (void *, const char *, int));

void *CRYPTO_malloc(size_t num, const char *file, int line);
void *CRYPTO_zalloc(size_t num, const char *file, int line);
void *CRYPTO_memdup(const void *str, size_t siz, const char *file, int line);
char *CRYPTO_strdup(const char *str, const char *file, int line);
char *CRYPTO_strndup(const char *str, size_t s, const char *file, int line);
void CRYPTO_free(void *ptr, const char *file, int line);
void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line);
void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line);
void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num,
                           const char *file, int line);

int CRYPTO_secure_malloc_init(size_t sz, int minsize);
int CRYPTO_secure_malloc_done(void);
void *CRYPTO_secure_malloc(size_t num, const char *file, int line);
void *CRYPTO_secure_zalloc(size_t num, const char *file, int line);
void CRYPTO_secure_free(void *ptr, const char *file, int line);
void CRYPTO_secure_clear_free(void *ptr, size_t num,
                              const char *file, int line);
int CRYPTO_secure_allocated(const void *ptr);
int CRYPTO_secure_malloc_initialized(void);
size_t CRYPTO_secure_actual_size(void *ptr);
size_t CRYPTO_secure_used(void);

void OPENSSL_cleanse(void *ptr, size_t len);
# 322 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
_Noreturn void OPENSSL_die(const char *assertion, const char *file, int line);






int OPENSSL_isservice(void);

int FIPS_mode(void);
int FIPS_mode_set(int r);

void OPENSSL_init(void);

void OPENSSL_fork_prepare(void);
void OPENSSL_fork_parent(void);
void OPENSSL_fork_child(void);


struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result);
int OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec);
int OPENSSL_gmtime_diff(int *pday, int *psec,
                        const struct tm *from, const struct tm *to);
# 353 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len);
# 387 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
void OPENSSL_cleanup(void);
int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
int OPENSSL_atexit(void (*handler)(void));
void OPENSSL_thread_stop(void);


OPENSSL_INIT_SETTINGS *OPENSSL_INIT_new(void);
# 402 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *settings);
# 415 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
# 1 "../intel-sgx-ssl/Linux/package/include/pthread.h" 1
# 37 "../intel-sgx-ssl/Linux/package/include/pthread.h"
typedef int pthread_once_t;
typedef unsigned int pthread_key_t;
typedef unsigned long int pthread_t;
# 416 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h" 2
typedef pthread_once_t CRYPTO_ONCE;
typedef pthread_key_t CRYPTO_THREAD_LOCAL;
typedef pthread_t CRYPTO_THREAD_ID;
# 431 "../intel-sgx-ssl/Linux/package/include/openssl/crypto.h"
int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *));
void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key);
int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val);
int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key);

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void);
int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b);
# 21 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h" 2
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/bioerr.h" 1
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/bioerr.h"
int ERR_load_BIO_strings(void);
# 22 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h" 2
# 177 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h"
typedef union bio_addr_st BIO_ADDR;
typedef struct bio_addrinfo_st BIO_ADDRINFO;

int BIO_get_new_index(void);
void BIO_set_flags(BIO *b, int flags);
int BIO_test_flags(const BIO *b, int flags);
void BIO_clear_flags(BIO *b, int flags);
# 239 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h"
typedef long (*BIO_callback_fn)(BIO *b, int oper, const char *argp, int argi,
                                long argl, long ret);
typedef long (*BIO_callback_fn_ex)(BIO *b, int oper, const char *argp,
                                   size_t len, int argi,
                                   long argl, int ret, size_t *processed);
BIO_callback_fn BIO_get_callback(const BIO *b);
void BIO_set_callback(BIO *b, BIO_callback_fn callback);

BIO_callback_fn_ex BIO_get_callback_ex(const BIO *b);
void BIO_set_callback_ex(BIO *b, BIO_callback_fn_ex callback);

char *BIO_get_callback_arg(const BIO *b);
void BIO_set_callback_arg(BIO *b, char *arg);

typedef struct bio_method_st BIO_METHOD;

const char *BIO_method_name(const BIO *b);
int BIO_method_type(const BIO *b);

typedef int BIO_info_cb(BIO *, int, int);
typedef BIO_info_cb bio_info_cb;

struct stack_st_BIO; typedef int (*sk_BIO_compfunc)(const BIO * const *a, const BIO *const *b); typedef void (*sk_BIO_freefunc)(BIO *a); typedef BIO * (*sk_BIO_copyfunc)(const BIO *a); static __attribute__((unused)) inline int sk_BIO_num(const struct stack_st_BIO *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline BIO *sk_BIO_value(const struct stack_st_BIO *sk, int idx) { return (BIO *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_BIO *sk_BIO_new(sk_BIO_compfunc compare) { return (struct stack_st_BIO *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_BIO *sk_BIO_new_null(void) { return (struct stack_st_BIO *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_BIO *sk_BIO_new_reserve(sk_BIO_compfunc compare, int n) { return (struct stack_st_BIO *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_BIO_reserve(struct stack_st_BIO *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_BIO_free(struct stack_st_BIO *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_BIO_zero(struct stack_st_BIO *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline BIO *sk_BIO_delete(struct stack_st_BIO *sk, int i) { return (BIO *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline BIO *sk_BIO_delete_ptr(struct stack_st_BIO *sk, BIO *ptr) { return (BIO *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_BIO_push(struct stack_st_BIO *sk, BIO *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_BIO_unshift(struct stack_st_BIO *sk, BIO *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline BIO *sk_BIO_pop(struct stack_st_BIO *sk) { return (BIO *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline BIO *sk_BIO_shift(struct stack_st_BIO *sk) { return (BIO *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_BIO_pop_free(struct stack_st_BIO *sk, sk_BIO_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_BIO_insert(struct stack_st_BIO *sk, BIO *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline BIO *sk_BIO_set(struct stack_st_BIO *sk, int idx, BIO *ptr) { return (BIO *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_BIO_find(struct stack_st_BIO *sk, BIO *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_BIO_find_ex(struct stack_st_BIO *sk, BIO *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_BIO_sort(struct stack_st_BIO *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_BIO_is_sorted(const struct stack_st_BIO *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_BIO * sk_BIO_dup(const struct stack_st_BIO *sk) { return (struct stack_st_BIO *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_BIO *sk_BIO_deep_copy(const struct stack_st_BIO *sk, sk_BIO_copyfunc copyfunc, sk_BIO_freefunc freefunc) { return (struct stack_st_BIO *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_BIO_compfunc sk_BIO_set_cmp_func(struct stack_st_BIO *sk, sk_BIO_compfunc compare) { return (sk_BIO_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }


typedef int asn1_ps_func (BIO *b, unsigned char **pbuf, int *plen,
                          void *parg);
# 490 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h"
size_t BIO_ctrl_pending(BIO *b);
size_t BIO_ctrl_wpending(BIO *b);
# 510 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h"
size_t BIO_ctrl_get_write_guarantee(BIO *b);
size_t BIO_ctrl_get_read_request(BIO *b);
int BIO_ctrl_reset_read_request(BIO *b);
# 532 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h"
int BIO_set_ex_data(BIO *bio, int idx, void *data);
void *BIO_get_ex_data(BIO *bio, int idx);
uint64_t BIO_number_read(BIO *bio);
uint64_t BIO_number_written(BIO *bio);


int BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix,
                        asn1_ps_func *prefix_free);
int BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix,
                        asn1_ps_func **pprefix_free);
int BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix,
                        asn1_ps_func *suffix_free);
int BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix,
                        asn1_ps_func **psuffix_free);

const BIO_METHOD *BIO_s_file(void);
BIO *BIO_new_file(const char *filename, const char *mode);



BIO *BIO_new(const BIO_METHOD *type);
int BIO_free(BIO *a);
void BIO_set_data(BIO *a, void *ptr);
void *BIO_get_data(BIO *a);
void BIO_set_init(BIO *a, int init);
int BIO_get_init(BIO *a);
void BIO_set_shutdown(BIO *a, int shut);
int BIO_get_shutdown(BIO *a);
void BIO_vfree(BIO *a);
int BIO_up_ref(BIO *a);
int BIO_read(BIO *b, void *data, int dlen);
int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);
int BIO_gets(BIO *bp, char *buf, int size);
int BIO_write(BIO *b, const void *data, int dlen);
int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);
int BIO_puts(BIO *bp, const char *buf);
int BIO_indent(BIO *b, int indent, int max);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);
void *BIO_ptr_ctrl(BIO *bp, int cmd, long larg);
long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);
BIO *BIO_push(BIO *b, BIO *append);
BIO *BIO_pop(BIO *b);
void BIO_free_all(BIO *a);
BIO *BIO_find_type(BIO *b, int bio_type);
BIO *BIO_next(BIO *b);
void BIO_set_next(BIO *b, BIO *next);
BIO *BIO_get_retry_BIO(BIO *bio, int *reason);
int BIO_get_retry_reason(BIO *bio);
void BIO_set_retry_reason(BIO *bio, int reason);
BIO *BIO_dup_chain(BIO *in);

int BIO_nread0(BIO *bio, char **buf);
int BIO_nread(BIO *bio, char **buf, int num);
int BIO_nwrite0(BIO *bio, char **buf);
int BIO_nwrite(BIO *bio, char **buf, int num);

long BIO_debug_callback(BIO *bio, int cmd, const char *argp, int argi,
                        long argl, long ret);

const BIO_METHOD *BIO_s_mem(void);
const BIO_METHOD *BIO_s_secmem(void);
BIO *BIO_new_mem_buf(const void *buf, int len);

const BIO_METHOD *BIO_s_socket(void);
const BIO_METHOD *BIO_s_connect(void);
const BIO_METHOD *BIO_s_accept(void);

const BIO_METHOD *BIO_s_fd(void);
const BIO_METHOD *BIO_s_log(void);
const BIO_METHOD *BIO_s_bio(void);
const BIO_METHOD *BIO_s_null(void);
const BIO_METHOD *BIO_f_null(void);
const BIO_METHOD *BIO_f_buffer(void);
const BIO_METHOD *BIO_f_linebuffer(void);
const BIO_METHOD *BIO_f_nbio_test(void);

const BIO_METHOD *BIO_s_datagram(void);
int BIO_dgram_non_fatal_error(int error);
BIO *BIO_new_dgram(int fd, int close_flag);
# 627 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h"
int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int error);


int BIO_fd_should_retry(int i);
int BIO_fd_non_fatal_error(int error);
int BIO_dump_cb(int (*cb) (const void *data, size_t len, void *u),
                void *u, const char *s, int len);
int BIO_dump_indent_cb(int (*cb) (const void *data, size_t len, void *u),
                       void *u, const char *s, int len, int indent);
int BIO_dump(BIO *b, const char *bytes, int len);
int BIO_dump_indent(BIO *b, const char *bytes, int len, int indent);




int BIO_hex_string(BIO *out, int indent, int width, unsigned char *data,
                   int datalen);


BIO_ADDR *BIO_ADDR_new(void);
int BIO_ADDR_rawmake(BIO_ADDR *ap, int family,
                     const void *where, size_t wherelen, unsigned short port);
void BIO_ADDR_free(BIO_ADDR *);
void BIO_ADDR_clear(BIO_ADDR *ap);
int BIO_ADDR_family(const BIO_ADDR *ap);
int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l);
unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap);
char *BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric);
char *BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric);
char *BIO_ADDR_path_string(const BIO_ADDR *ap);

const BIO_ADDRINFO *BIO_ADDRINFO_next(const BIO_ADDRINFO *bai);
int BIO_ADDRINFO_family(const BIO_ADDRINFO *bai);
int BIO_ADDRINFO_socktype(const BIO_ADDRINFO *bai);
int BIO_ADDRINFO_protocol(const BIO_ADDRINFO *bai);
const BIO_ADDR *BIO_ADDRINFO_address(const BIO_ADDRINFO *bai);
void BIO_ADDRINFO_free(BIO_ADDRINFO *bai);

enum BIO_hostserv_priorities {
    BIO_PARSE_PRIO_HOST, BIO_PARSE_PRIO_SERV
};
int BIO_parse_hostserv(const char *hostserv, char **host, char **service,
                       enum BIO_hostserv_priorities hostserv_prio);
enum BIO_lookup_type {
    BIO_LOOKUP_CLIENT, BIO_LOOKUP_SERVER
};
int BIO_lookup(const char *host, const char *service,
               enum BIO_lookup_type lookup_type,
               int family, int socktype, BIO_ADDRINFO **res);
int BIO_lookup_ex(const char *host, const char *service,
                  int lookup_type, int family, int socktype, int protocol,
                  BIO_ADDRINFO **res);
int BIO_sock_error(int sock);
int BIO_socket_ioctl(int fd, long type, void *arg);
int BIO_socket_nbio(int fd, int mode);
int BIO_sock_init(void);



int BIO_set_tcp_ndelay(int sock, int turn_on);

struct hostent *BIO_gethostbyname(const char *name) __attribute__ ((deprecated));
int BIO_get_port(const char *str, unsigned short *port_ptr) __attribute__ ((deprecated));
int BIO_get_host_ip(const char *str, unsigned char *ip) __attribute__ ((deprecated));
int BIO_get_accept_socket(char *host_port, int mode) __attribute__ ((deprecated));
int BIO_accept(int sock, char **ip_port) __attribute__ ((deprecated));

union BIO_sock_info_u {
    BIO_ADDR *addr;
};
enum BIO_sock_info_type {
    BIO_SOCK_INFO_ADDRESS
};
int BIO_sock_info(int sock,
                  enum BIO_sock_info_type type, union BIO_sock_info_u *info);







int BIO_socket(int domain, int socktype, int protocol, int options);
int BIO_connect(int sock, const BIO_ADDR *addr, int options);
int BIO_bind(int sock, const BIO_ADDR *addr, int options);
int BIO_listen(int sock, const BIO_ADDR *addr, int options);
int BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options);
int BIO_closesocket(int sock);

BIO *BIO_new_socket(int sock, int close_flag);
BIO *BIO_new_connect(const char *host_port);
BIO *BIO_new_accept(const char *host_port);


BIO *BIO_new_fd(int fd, int close_flag);

int BIO_new_bio_pair(BIO **bio1, size_t writebuf1,
                     BIO **bio2, size_t writebuf2);






void BIO_copy_next_retry(BIO *b);
# 755 "../intel-sgx-ssl/Linux/package/include/openssl/bio.h"
int BIO_printf(BIO *bio, const char *format, ...)
__attribute__((__format__(__gnu_printf__, 2, 3)));
int BIO_vprintf(BIO *bio, const char *format, va_list args)
__attribute__((__format__(__gnu_printf__, 2, 0)));
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
__attribute__((__format__(__gnu_printf__, 3, 4)));
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
__attribute__((__format__(__gnu_printf__, 3, 0)));




BIO_METHOD *BIO_meth_new(int type, const char *name);
void BIO_meth_free(BIO_METHOD *biom);
int (*BIO_meth_get_write(const BIO_METHOD *biom)) (BIO *, const char *, int);
int (*BIO_meth_get_write_ex(const BIO_METHOD *biom)) (BIO *, const char *, size_t,
                                                size_t *);
int BIO_meth_set_write(BIO_METHOD *biom,
                       int (*write) (BIO *, const char *, int));
int BIO_meth_set_write_ex(BIO_METHOD *biom,
                       int (*bwrite) (BIO *, const char *, size_t, size_t *));
int (*BIO_meth_get_read(const BIO_METHOD *biom)) (BIO *, char *, int);
int (*BIO_meth_get_read_ex(const BIO_METHOD *biom)) (BIO *, char *, size_t, size_t *);
int BIO_meth_set_read(BIO_METHOD *biom,
                      int (*read) (BIO *, char *, int));
int BIO_meth_set_read_ex(BIO_METHOD *biom,
                         int (*bread) (BIO *, char *, size_t, size_t *));
int (*BIO_meth_get_puts(const BIO_METHOD *biom)) (BIO *, const char *);
int BIO_meth_set_puts(BIO_METHOD *biom,
                      int (*puts) (BIO *, const char *));
int (*BIO_meth_get_gets(const BIO_METHOD *biom)) (BIO *, char *, int);
int BIO_meth_set_gets(BIO_METHOD *biom,
                      int (*gets) (BIO *, char *, int));
long (*BIO_meth_get_ctrl(const BIO_METHOD *biom)) (BIO *, int, long, void *);
int BIO_meth_set_ctrl(BIO_METHOD *biom,
                      long (*ctrl) (BIO *, int, long, void *));
int (*BIO_meth_get_create(const BIO_METHOD *bion)) (BIO *);
int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
int (*BIO_meth_get_destroy(const BIO_METHOD *biom)) (BIO *);
int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))
                                 (BIO *, int, BIO_info_cb *);
int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
                               long (*callback_ctrl) (BIO *, int,
                                                      BIO_info_cb *));
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h" 2

# 1 "../intel-sgx-ssl/Linux/package/include/openssl/asn1err.h" 1
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/asn1err.h"
int ERR_load_ASN1_strings(void);
# 19 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h" 2




# 1 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h" 1
# 18 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h" 1
# 19 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h" 2


# 1 "../intel-sgx-ssl/Linux/package/include/openssl/bnerr.h" 1
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/bnerr.h"
int ERR_load_BN_strings(void);
# 22 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h" 2
# 70 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h"
void BN_set_flags(BIGNUM *b, int n);
int BN_get_flags(const BIGNUM *b, int n);
# 88 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h"
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);


int BN_GENCB_call(BN_GENCB *cb, int a, int b);

BN_GENCB *BN_GENCB_new(void);
void BN_GENCB_free(BN_GENCB *cb);


void BN_GENCB_set_old(BN_GENCB *gencb, void (*callback) (int, int, void *),
                      void *cb_arg);


void BN_GENCB_set(BN_GENCB *gencb, int (*callback) (int, int, BN_GENCB *),
                  void *cb_arg);

void *BN_GENCB_get_arg(BN_GENCB *cb);
# 183 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h"
int BN_abs_is_word(const BIGNUM *a, const unsigned long w);
int BN_is_zero(const BIGNUM *a);
int BN_is_one(const BIGNUM *a);
int BN_is_word(const BIGNUM *a, const unsigned long w);
int BN_is_odd(const BIGNUM *a);



void BN_zero_ex(BIGNUM *a);







const BIGNUM *BN_value_one(void);
char *BN_options(void);
BN_CTX *BN_CTX_new(void);
BN_CTX *BN_CTX_secure_new(void);
void BN_CTX_free(BN_CTX *c);
void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_num_bits(const BIGNUM *a);
int BN_num_bits_word(unsigned long l);
int BN_security_bits(int L, int N);
BIGNUM *BN_new(void);
BIGNUM *BN_secure_new(void);
void BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);




void BN_set_negative(BIGNUM *b, int n);




int BN_is_negative(const BIGNUM *b);

int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
           BN_CTX *ctx);

int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m);
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m);
int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
                  BN_CTX *ctx);
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);

unsigned long BN_mod_word(const BIGNUM *a, unsigned long w);
unsigned long BN_div_word(BIGNUM *a, unsigned long w);
int BN_mul_word(BIGNUM *a, unsigned long w);
int BN_add_word(BIGNUM *a, unsigned long w);
int BN_sub_word(BIGNUM *a, unsigned long w);
int BN_set_word(BIGNUM *a, unsigned long w);
unsigned long BN_get_word(const BIGNUM *a);

int BN_cmp(const BIGNUM *a, const BIGNUM *b);
void BN_free(BIGNUM *a);
int BN_is_bit_set(const BIGNUM *a, int n);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
               const BIGNUM *m, BN_CTX *ctx);
int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont);
int BN_mod_exp_mont_word(BIGNUM *r, unsigned long a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
                     const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
                     BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx);

int BN_mask_bits(BIGNUM *a, int n);



int BN_print(BIO *bio, const BIGNUM *a);
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
void BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
char *BN_bn2hex(const BIGNUM *a);
char *BN_bn2dec(const BIGNUM *a);
int BN_hex2bn(BIGNUM **a, const char *str);
int BN_dec2bn(BIGNUM **a, const char *str);
int BN_asc2bn(BIGNUM **a, const char *str);
int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);


BIGNUM *BN_mod_inverse(BIGNUM *ret,
                       const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
                    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

void BN_consttime_swap(unsigned long swap, BIGNUM *a, BIGNUM *b, int nwords);


BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, void (*callback) (int, int, void *), void *cb_arg) __attribute__ ((deprecated));





int BN_is_prime(const BIGNUM *p, int nchecks, void (*callback) (int, int, void *), BN_CTX *ctx, void *cb_arg) __attribute__ ((deprecated));



int BN_is_prime_fasttest(const BIGNUM *p, int nchecks, void (*callback) (int, int, void *), BN_CTX *ctx, void *cb_arg, int do_trial_division) __attribute__ ((deprecated));






int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add,
                         const BIGNUM *rem, BN_GENCB *cb);
int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
int BN_is_prime_fasttest_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx,
                            int do_trial_division, BN_GENCB *cb);

int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx);

int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                            const BIGNUM *Xp, const BIGNUM *Xp1,
                            const BIGNUM *Xp2, const BIGNUM *e, BN_CTX *ctx,
                            BN_GENCB *cb);
int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2, BIGNUM *Xp1,
                              BIGNUM *Xp2, const BIGNUM *Xp, const BIGNUM *e,
                              BN_CTX *ctx, BN_GENCB *cb);

BN_MONT_CTX *BN_MONT_CTX_new(void);
int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx);
int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                     BN_CTX *ctx);
int BN_from_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                       BN_CTX *ctx);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from);
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
                                    const BIGNUM *mod, BN_CTX *ctx);





BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
void BN_BLINDING_free(BN_BLINDING *b);
int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *);
int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,
                          BN_CTX *);

int BN_BLINDING_is_current_thread(BN_BLINDING *b);
void BN_BLINDING_set_current_thread(BN_BLINDING *b);
int BN_BLINDING_lock(BN_BLINDING *b);
int BN_BLINDING_unlock(BN_BLINDING *b);

unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
                                      const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
                                      int (*bn_mod_exp) (BIGNUM *r,
                                                         const BIGNUM *a,
                                                         const BIGNUM *p,
                                                         const BIGNUM *m,
                                                         BN_CTX *ctx,
                                                         BN_MONT_CTX *m_ctx),
                                      BN_MONT_CTX *m_ctx);

void BN_set_params(int mul, int high, int low, int mont) __attribute__ ((deprecated));
int BN_get_params(int which) __attribute__ ((deprecated));


BN_RECP_CTX *BN_RECP_CTX_new(void);
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *rdiv, BN_CTX *ctx);
int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
                          BN_RECP_CTX *recp, BN_CTX *ctx);
int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx);
int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                BN_RECP_CTX *recp, BN_CTX *ctx);
# 491 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h"
int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

const BIGNUM *BN_get0_nist_prime_192(void);
const BIGNUM *BN_get0_nist_prime_224(void);
const BIGNUM *BN_get0_nist_prime_256(void);
const BIGNUM *BN_get0_nist_prime_384(void);
const BIGNUM *BN_get0_nist_prime_521(void);

int (*BN_nist_mod_func(const BIGNUM *p)) (BIGNUM *r, const BIGNUM *a,
                                          const BIGNUM *field, BN_CTX *ctx);

int BN_generate_dsa_nonce(BIGNUM *out, const BIGNUM *range,
                          const BIGNUM *priv, const unsigned char *message,
                          size_t message_len, BN_CTX *ctx);


BIGNUM *BN_get_rfc2409_prime_768(BIGNUM *bn);
BIGNUM *BN_get_rfc2409_prime_1024(BIGNUM *bn);


BIGNUM *BN_get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_3072(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_4096(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_8192(BIGNUM *bn);
# 533 "../intel-sgx-ssl/Linux/package/include/openssl/bn.h"
int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom);
# 24 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h" 2
# 118 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
    struct X509_algor_st;
struct stack_st_X509_ALGOR; typedef int (*sk_X509_ALGOR_compfunc)(const X509_ALGOR * const *a, const X509_ALGOR *const *b); typedef void (*sk_X509_ALGOR_freefunc)(X509_ALGOR *a); typedef X509_ALGOR * (*sk_X509_ALGOR_copyfunc)(const X509_ALGOR *a); static __attribute__((unused)) inline int sk_X509_ALGOR_num(const struct stack_st_X509_ALGOR *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline X509_ALGOR *sk_X509_ALGOR_value(const struct stack_st_X509_ALGOR *sk, int idx) { return (X509_ALGOR *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_X509_ALGOR *sk_X509_ALGOR_new(sk_X509_ALGOR_compfunc compare) { return (struct stack_st_X509_ALGOR *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_X509_ALGOR *sk_X509_ALGOR_new_null(void) { return (struct stack_st_X509_ALGOR *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_X509_ALGOR *sk_X509_ALGOR_new_reserve(sk_X509_ALGOR_compfunc compare, int n) { return (struct stack_st_X509_ALGOR *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_X509_ALGOR_reserve(struct stack_st_X509_ALGOR *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_X509_ALGOR_free(struct stack_st_X509_ALGOR *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_X509_ALGOR_zero(struct stack_st_X509_ALGOR *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline X509_ALGOR *sk_X509_ALGOR_delete(struct stack_st_X509_ALGOR *sk, int i) { return (X509_ALGOR *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline X509_ALGOR *sk_X509_ALGOR_delete_ptr(struct stack_st_X509_ALGOR *sk, X509_ALGOR *ptr) { return (X509_ALGOR *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_X509_ALGOR_push(struct stack_st_X509_ALGOR *sk, X509_ALGOR *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_X509_ALGOR_unshift(struct stack_st_X509_ALGOR *sk, X509_ALGOR *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline X509_ALGOR *sk_X509_ALGOR_pop(struct stack_st_X509_ALGOR *sk) { return (X509_ALGOR *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline X509_ALGOR *sk_X509_ALGOR_shift(struct stack_st_X509_ALGOR *sk) { return (X509_ALGOR *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_X509_ALGOR_pop_free(struct stack_st_X509_ALGOR *sk, sk_X509_ALGOR_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_X509_ALGOR_insert(struct stack_st_X509_ALGOR *sk, X509_ALGOR *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline X509_ALGOR *sk_X509_ALGOR_set(struct stack_st_X509_ALGOR *sk, int idx, X509_ALGOR *ptr) { return (X509_ALGOR *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_X509_ALGOR_find(struct stack_st_X509_ALGOR *sk, X509_ALGOR *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_X509_ALGOR_find_ex(struct stack_st_X509_ALGOR *sk, X509_ALGOR *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_X509_ALGOR_sort(struct stack_st_X509_ALGOR *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_X509_ALGOR_is_sorted(const struct stack_st_X509_ALGOR *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_X509_ALGOR * sk_X509_ALGOR_dup(const struct stack_st_X509_ALGOR *sk) { return (struct stack_st_X509_ALGOR *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_X509_ALGOR *sk_X509_ALGOR_deep_copy(const struct stack_st_X509_ALGOR *sk, sk_X509_ALGOR_copyfunc copyfunc, sk_X509_ALGOR_freefunc freefunc) { return (struct stack_st_X509_ALGOR *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_X509_ALGOR_compfunc sk_X509_ALGOR_set_cmp_func(struct stack_st_X509_ALGOR *sk, sk_X509_ALGOR_compfunc compare) { return (sk_X509_ALGOR_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }
# 146 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;





    long flags;
};







typedef struct ASN1_ENCODING_st {
    unsigned char *enc;
    long len;
    int modified;
} ASN1_ENCODING;
# 186 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
typedef struct asn1_string_table_st {
    int nid;
    long minsize;
    long maxsize;
    unsigned long mask;
    unsigned long flags;
} ASN1_STRING_TABLE;

struct stack_st_ASN1_STRING_TABLE; typedef int (*sk_ASN1_STRING_TABLE_compfunc)(const ASN1_STRING_TABLE * const *a, const ASN1_STRING_TABLE *const *b); typedef void (*sk_ASN1_STRING_TABLE_freefunc)(ASN1_STRING_TABLE *a); typedef ASN1_STRING_TABLE * (*sk_ASN1_STRING_TABLE_copyfunc)(const ASN1_STRING_TABLE *a); static __attribute__((unused)) inline int sk_ASN1_STRING_TABLE_num(const struct stack_st_ASN1_STRING_TABLE *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_value(const struct stack_st_ASN1_STRING_TABLE *sk, int idx) { return (ASN1_STRING_TABLE *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_new(sk_ASN1_STRING_TABLE_compfunc compare) { return (struct stack_st_ASN1_STRING_TABLE *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_new_null(void) { return (struct stack_st_ASN1_STRING_TABLE *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_new_reserve(sk_ASN1_STRING_TABLE_compfunc compare, int n) { return (struct stack_st_ASN1_STRING_TABLE *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_ASN1_STRING_TABLE_reserve(struct stack_st_ASN1_STRING_TABLE *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_ASN1_STRING_TABLE_free(struct stack_st_ASN1_STRING_TABLE *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_STRING_TABLE_zero(struct stack_st_ASN1_STRING_TABLE *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_delete(struct stack_st_ASN1_STRING_TABLE *sk, int i) { return (ASN1_STRING_TABLE *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_delete_ptr(struct stack_st_ASN1_STRING_TABLE *sk, ASN1_STRING_TABLE *ptr) { return (ASN1_STRING_TABLE *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_STRING_TABLE_push(struct stack_st_ASN1_STRING_TABLE *sk, ASN1_STRING_TABLE *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_STRING_TABLE_unshift(struct stack_st_ASN1_STRING_TABLE *sk, ASN1_STRING_TABLE *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_pop(struct stack_st_ASN1_STRING_TABLE *sk) { return (ASN1_STRING_TABLE *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_shift(struct stack_st_ASN1_STRING_TABLE *sk) { return (ASN1_STRING_TABLE *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_STRING_TABLE_pop_free(struct stack_st_ASN1_STRING_TABLE *sk, sk_ASN1_STRING_TABLE_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_ASN1_STRING_TABLE_insert(struct stack_st_ASN1_STRING_TABLE *sk, ASN1_STRING_TABLE *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_set(struct stack_st_ASN1_STRING_TABLE *sk, int idx, ASN1_STRING_TABLE *ptr) { return (ASN1_STRING_TABLE *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_STRING_TABLE_find(struct stack_st_ASN1_STRING_TABLE *sk, ASN1_STRING_TABLE *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_STRING_TABLE_find_ex(struct stack_st_ASN1_STRING_TABLE *sk, ASN1_STRING_TABLE *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_ASN1_STRING_TABLE_sort(struct stack_st_ASN1_STRING_TABLE *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_ASN1_STRING_TABLE_is_sorted(const struct stack_st_ASN1_STRING_TABLE *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_STRING_TABLE * sk_ASN1_STRING_TABLE_dup(const struct stack_st_ASN1_STRING_TABLE *sk) { return (struct stack_st_ASN1_STRING_TABLE *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_STRING_TABLE *sk_ASN1_STRING_TABLE_deep_copy(const struct stack_st_ASN1_STRING_TABLE *sk, sk_ASN1_STRING_TABLE_copyfunc copyfunc, sk_ASN1_STRING_TABLE_freefunc freefunc) { return (struct stack_st_ASN1_STRING_TABLE *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_ASN1_STRING_TABLE_compfunc sk_ASN1_STRING_TABLE_set_cmp_func(struct stack_st_ASN1_STRING_TABLE *sk, sk_ASN1_STRING_TABLE_compfunc compare) { return (sk_ASN1_STRING_TABLE_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }
# 210 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ASN1_TLC_st ASN1_TLC;

typedef struct ASN1_VALUE_st ASN1_VALUE;
# 277 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
typedef void *d2i_of_void(void **,const unsigned char **,long); typedef int i2d_of_void(void *,unsigned char **);
# 318 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
typedef const ASN1_ITEM ASN1_ITEM_EXP;
# 438 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
struct stack_st_ASN1_INTEGER; typedef int (*sk_ASN1_INTEGER_compfunc)(const ASN1_INTEGER * const *a, const ASN1_INTEGER *const *b); typedef void (*sk_ASN1_INTEGER_freefunc)(ASN1_INTEGER *a); typedef ASN1_INTEGER * (*sk_ASN1_INTEGER_copyfunc)(const ASN1_INTEGER *a); static __attribute__((unused)) inline int sk_ASN1_INTEGER_num(const struct stack_st_ASN1_INTEGER *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_INTEGER *sk_ASN1_INTEGER_value(const struct stack_st_ASN1_INTEGER *sk, int idx) { return (ASN1_INTEGER *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_ASN1_INTEGER *sk_ASN1_INTEGER_new(sk_ASN1_INTEGER_compfunc compare) { return (struct stack_st_ASN1_INTEGER *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_ASN1_INTEGER *sk_ASN1_INTEGER_new_null(void) { return (struct stack_st_ASN1_INTEGER *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_ASN1_INTEGER *sk_ASN1_INTEGER_new_reserve(sk_ASN1_INTEGER_compfunc compare, int n) { return (struct stack_st_ASN1_INTEGER *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_ASN1_INTEGER_reserve(struct stack_st_ASN1_INTEGER *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_ASN1_INTEGER_free(struct stack_st_ASN1_INTEGER *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_INTEGER_zero(struct stack_st_ASN1_INTEGER *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_INTEGER *sk_ASN1_INTEGER_delete(struct stack_st_ASN1_INTEGER *sk, int i) { return (ASN1_INTEGER *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline ASN1_INTEGER *sk_ASN1_INTEGER_delete_ptr(struct stack_st_ASN1_INTEGER *sk, ASN1_INTEGER *ptr) { return (ASN1_INTEGER *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_INTEGER_push(struct stack_st_ASN1_INTEGER *sk, ASN1_INTEGER *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_INTEGER_unshift(struct stack_st_ASN1_INTEGER *sk, ASN1_INTEGER *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline ASN1_INTEGER *sk_ASN1_INTEGER_pop(struct stack_st_ASN1_INTEGER *sk) { return (ASN1_INTEGER *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_INTEGER *sk_ASN1_INTEGER_shift(struct stack_st_ASN1_INTEGER *sk) { return (ASN1_INTEGER *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_INTEGER_pop_free(struct stack_st_ASN1_INTEGER *sk, sk_ASN1_INTEGER_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_ASN1_INTEGER_insert(struct stack_st_ASN1_INTEGER *sk, ASN1_INTEGER *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline ASN1_INTEGER *sk_ASN1_INTEGER_set(struct stack_st_ASN1_INTEGER *sk, int idx, ASN1_INTEGER *ptr) { return (ASN1_INTEGER *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_INTEGER_find(struct stack_st_ASN1_INTEGER *sk, ASN1_INTEGER *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_INTEGER_find_ex(struct stack_st_ASN1_INTEGER *sk, ASN1_INTEGER *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_ASN1_INTEGER_sort(struct stack_st_ASN1_INTEGER *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_ASN1_INTEGER_is_sorted(const struct stack_st_ASN1_INTEGER *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_INTEGER * sk_ASN1_INTEGER_dup(const struct stack_st_ASN1_INTEGER *sk) { return (struct stack_st_ASN1_INTEGER *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_INTEGER *sk_ASN1_INTEGER_deep_copy(const struct stack_st_ASN1_INTEGER *sk, sk_ASN1_INTEGER_copyfunc copyfunc, sk_ASN1_INTEGER_freefunc freefunc) { return (struct stack_st_ASN1_INTEGER *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_ASN1_INTEGER_compfunc sk_ASN1_INTEGER_set_cmp_func(struct stack_st_ASN1_INTEGER *sk, sk_ASN1_INTEGER_compfunc compare) { return (sk_ASN1_INTEGER_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }

struct stack_st_ASN1_GENERALSTRING; typedef int (*sk_ASN1_GENERALSTRING_compfunc)(const ASN1_GENERALSTRING * const *a, const ASN1_GENERALSTRING *const *b); typedef void (*sk_ASN1_GENERALSTRING_freefunc)(ASN1_GENERALSTRING *a); typedef ASN1_GENERALSTRING * (*sk_ASN1_GENERALSTRING_copyfunc)(const ASN1_GENERALSTRING *a); static __attribute__((unused)) inline int sk_ASN1_GENERALSTRING_num(const struct stack_st_ASN1_GENERALSTRING *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_value(const struct stack_st_ASN1_GENERALSTRING *sk, int idx) { return (ASN1_GENERALSTRING *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_new(sk_ASN1_GENERALSTRING_compfunc compare) { return (struct stack_st_ASN1_GENERALSTRING *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_new_null(void) { return (struct stack_st_ASN1_GENERALSTRING *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_new_reserve(sk_ASN1_GENERALSTRING_compfunc compare, int n) { return (struct stack_st_ASN1_GENERALSTRING *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_ASN1_GENERALSTRING_reserve(struct stack_st_ASN1_GENERALSTRING *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_ASN1_GENERALSTRING_free(struct stack_st_ASN1_GENERALSTRING *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_GENERALSTRING_zero(struct stack_st_ASN1_GENERALSTRING *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_delete(struct stack_st_ASN1_GENERALSTRING *sk, int i) { return (ASN1_GENERALSTRING *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_delete_ptr(struct stack_st_ASN1_GENERALSTRING *sk, ASN1_GENERALSTRING *ptr) { return (ASN1_GENERALSTRING *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_GENERALSTRING_push(struct stack_st_ASN1_GENERALSTRING *sk, ASN1_GENERALSTRING *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_GENERALSTRING_unshift(struct stack_st_ASN1_GENERALSTRING *sk, ASN1_GENERALSTRING *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_pop(struct stack_st_ASN1_GENERALSTRING *sk) { return (ASN1_GENERALSTRING *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_shift(struct stack_st_ASN1_GENERALSTRING *sk) { return (ASN1_GENERALSTRING *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_GENERALSTRING_pop_free(struct stack_st_ASN1_GENERALSTRING *sk, sk_ASN1_GENERALSTRING_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_ASN1_GENERALSTRING_insert(struct stack_st_ASN1_GENERALSTRING *sk, ASN1_GENERALSTRING *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_set(struct stack_st_ASN1_GENERALSTRING *sk, int idx, ASN1_GENERALSTRING *ptr) { return (ASN1_GENERALSTRING *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_GENERALSTRING_find(struct stack_st_ASN1_GENERALSTRING *sk, ASN1_GENERALSTRING *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_GENERALSTRING_find_ex(struct stack_st_ASN1_GENERALSTRING *sk, ASN1_GENERALSTRING *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_ASN1_GENERALSTRING_sort(struct stack_st_ASN1_GENERALSTRING *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_ASN1_GENERALSTRING_is_sorted(const struct stack_st_ASN1_GENERALSTRING *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_GENERALSTRING * sk_ASN1_GENERALSTRING_dup(const struct stack_st_ASN1_GENERALSTRING *sk) { return (struct stack_st_ASN1_GENERALSTRING *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_GENERALSTRING *sk_ASN1_GENERALSTRING_deep_copy(const struct stack_st_ASN1_GENERALSTRING *sk, sk_ASN1_GENERALSTRING_copyfunc copyfunc, sk_ASN1_GENERALSTRING_freefunc freefunc) { return (struct stack_st_ASN1_GENERALSTRING *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_ASN1_GENERALSTRING_compfunc sk_ASN1_GENERALSTRING_set_cmp_func(struct stack_st_ASN1_GENERALSTRING *sk, sk_ASN1_GENERALSTRING_compfunc compare) { return (sk_ASN1_GENERALSTRING_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }

struct stack_st_ASN1_UTF8STRING; typedef int (*sk_ASN1_UTF8STRING_compfunc)(const ASN1_UTF8STRING * const *a, const ASN1_UTF8STRING *const *b); typedef void (*sk_ASN1_UTF8STRING_freefunc)(ASN1_UTF8STRING *a); typedef ASN1_UTF8STRING * (*sk_ASN1_UTF8STRING_copyfunc)(const ASN1_UTF8STRING *a); static __attribute__((unused)) inline int sk_ASN1_UTF8STRING_num(const struct stack_st_ASN1_UTF8STRING *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_UTF8STRING *sk_ASN1_UTF8STRING_value(const struct stack_st_ASN1_UTF8STRING *sk, int idx) { return (ASN1_UTF8STRING *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_ASN1_UTF8STRING *sk_ASN1_UTF8STRING_new(sk_ASN1_UTF8STRING_compfunc compare) { return (struct stack_st_ASN1_UTF8STRING *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_ASN1_UTF8STRING *sk_ASN1_UTF8STRING_new_null(void) { return (struct stack_st_ASN1_UTF8STRING *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_ASN1_UTF8STRING *sk_ASN1_UTF8STRING_new_reserve(sk_ASN1_UTF8STRING_compfunc compare, int n) { return (struct stack_st_ASN1_UTF8STRING *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_ASN1_UTF8STRING_reserve(struct stack_st_ASN1_UTF8STRING *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_ASN1_UTF8STRING_free(struct stack_st_ASN1_UTF8STRING *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_UTF8STRING_zero(struct stack_st_ASN1_UTF8STRING *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_UTF8STRING *sk_ASN1_UTF8STRING_delete(struct stack_st_ASN1_UTF8STRING *sk, int i) { return (ASN1_UTF8STRING *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline ASN1_UTF8STRING *sk_ASN1_UTF8STRING_delete_ptr(struct stack_st_ASN1_UTF8STRING *sk, ASN1_UTF8STRING *ptr) { return (ASN1_UTF8STRING *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_UTF8STRING_push(struct stack_st_ASN1_UTF8STRING *sk, ASN1_UTF8STRING *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_UTF8STRING_unshift(struct stack_st_ASN1_UTF8STRING *sk, ASN1_UTF8STRING *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline ASN1_UTF8STRING *sk_ASN1_UTF8STRING_pop(struct stack_st_ASN1_UTF8STRING *sk) { return (ASN1_UTF8STRING *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_UTF8STRING *sk_ASN1_UTF8STRING_shift(struct stack_st_ASN1_UTF8STRING *sk) { return (ASN1_UTF8STRING *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_UTF8STRING_pop_free(struct stack_st_ASN1_UTF8STRING *sk, sk_ASN1_UTF8STRING_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_ASN1_UTF8STRING_insert(struct stack_st_ASN1_UTF8STRING *sk, ASN1_UTF8STRING *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline ASN1_UTF8STRING *sk_ASN1_UTF8STRING_set(struct stack_st_ASN1_UTF8STRING *sk, int idx, ASN1_UTF8STRING *ptr) { return (ASN1_UTF8STRING *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_UTF8STRING_find(struct stack_st_ASN1_UTF8STRING *sk, ASN1_UTF8STRING *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_UTF8STRING_find_ex(struct stack_st_ASN1_UTF8STRING *sk, ASN1_UTF8STRING *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_ASN1_UTF8STRING_sort(struct stack_st_ASN1_UTF8STRING *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_ASN1_UTF8STRING_is_sorted(const struct stack_st_ASN1_UTF8STRING *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_UTF8STRING * sk_ASN1_UTF8STRING_dup(const struct stack_st_ASN1_UTF8STRING *sk) { return (struct stack_st_ASN1_UTF8STRING *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_UTF8STRING *sk_ASN1_UTF8STRING_deep_copy(const struct stack_st_ASN1_UTF8STRING *sk, sk_ASN1_UTF8STRING_copyfunc copyfunc, sk_ASN1_UTF8STRING_freefunc freefunc) { return (struct stack_st_ASN1_UTF8STRING *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_ASN1_UTF8STRING_compfunc sk_ASN1_UTF8STRING_set_cmp_func(struct stack_st_ASN1_UTF8STRING *sk, sk_ASN1_UTF8STRING_compfunc compare) { return (sk_ASN1_UTF8STRING_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }

typedef struct asn1_type_st {
    int type;
    union {
        char *ptr;
        ASN1_BOOLEAN boolean;
        ASN1_STRING *asn1_string;
        ASN1_OBJECT *object;
        ASN1_INTEGER *integer;
        ASN1_ENUMERATED *enumerated;
        ASN1_BIT_STRING *bit_string;
        ASN1_OCTET_STRING *octet_string;
        ASN1_PRINTABLESTRING *printablestring;
        ASN1_T61STRING *t61string;
        ASN1_IA5STRING *ia5string;
        ASN1_GENERALSTRING *generalstring;
        ASN1_BMPSTRING *bmpstring;
        ASN1_UNIVERSALSTRING *universalstring;
        ASN1_UTCTIME *utctime;
        ASN1_GENERALIZEDTIME *generalizedtime;
        ASN1_VISIBLESTRING *visiblestring;
        ASN1_UTF8STRING *utf8string;




        ASN1_STRING *set;
        ASN1_STRING *sequence;
        ASN1_VALUE *asn1_value;
    } value;
} ASN1_TYPE;

struct stack_st_ASN1_TYPE; typedef int (*sk_ASN1_TYPE_compfunc)(const ASN1_TYPE * const *a, const ASN1_TYPE *const *b); typedef void (*sk_ASN1_TYPE_freefunc)(ASN1_TYPE *a); typedef ASN1_TYPE * (*sk_ASN1_TYPE_copyfunc)(const ASN1_TYPE *a); static __attribute__((unused)) inline int sk_ASN1_TYPE_num(const struct stack_st_ASN1_TYPE *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_TYPE *sk_ASN1_TYPE_value(const struct stack_st_ASN1_TYPE *sk, int idx) { return (ASN1_TYPE *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_ASN1_TYPE *sk_ASN1_TYPE_new(sk_ASN1_TYPE_compfunc compare) { return (struct stack_st_ASN1_TYPE *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_ASN1_TYPE *sk_ASN1_TYPE_new_null(void) { return (struct stack_st_ASN1_TYPE *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_ASN1_TYPE *sk_ASN1_TYPE_new_reserve(sk_ASN1_TYPE_compfunc compare, int n) { return (struct stack_st_ASN1_TYPE *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_ASN1_TYPE_reserve(struct stack_st_ASN1_TYPE *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_ASN1_TYPE_free(struct stack_st_ASN1_TYPE *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_TYPE_zero(struct stack_st_ASN1_TYPE *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_TYPE *sk_ASN1_TYPE_delete(struct stack_st_ASN1_TYPE *sk, int i) { return (ASN1_TYPE *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline ASN1_TYPE *sk_ASN1_TYPE_delete_ptr(struct stack_st_ASN1_TYPE *sk, ASN1_TYPE *ptr) { return (ASN1_TYPE *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_TYPE_push(struct stack_st_ASN1_TYPE *sk, ASN1_TYPE *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_TYPE_unshift(struct stack_st_ASN1_TYPE *sk, ASN1_TYPE *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline ASN1_TYPE *sk_ASN1_TYPE_pop(struct stack_st_ASN1_TYPE *sk) { return (ASN1_TYPE *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_TYPE *sk_ASN1_TYPE_shift(struct stack_st_ASN1_TYPE *sk) { return (ASN1_TYPE *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_TYPE_pop_free(struct stack_st_ASN1_TYPE *sk, sk_ASN1_TYPE_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_ASN1_TYPE_insert(struct stack_st_ASN1_TYPE *sk, ASN1_TYPE *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline ASN1_TYPE *sk_ASN1_TYPE_set(struct stack_st_ASN1_TYPE *sk, int idx, ASN1_TYPE *ptr) { return (ASN1_TYPE *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_TYPE_find(struct stack_st_ASN1_TYPE *sk, ASN1_TYPE *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_TYPE_find_ex(struct stack_st_ASN1_TYPE *sk, ASN1_TYPE *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_ASN1_TYPE_sort(struct stack_st_ASN1_TYPE *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_ASN1_TYPE_is_sorted(const struct stack_st_ASN1_TYPE *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_TYPE * sk_ASN1_TYPE_dup(const struct stack_st_ASN1_TYPE *sk) { return (struct stack_st_ASN1_TYPE *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_TYPE *sk_ASN1_TYPE_deep_copy(const struct stack_st_ASN1_TYPE *sk, sk_ASN1_TYPE_copyfunc copyfunc, sk_ASN1_TYPE_freefunc freefunc) { return (struct stack_st_ASN1_TYPE *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_ASN1_TYPE_compfunc sk_ASN1_TYPE_set_cmp_func(struct stack_st_ASN1_TYPE *sk, sk_ASN1_TYPE_compfunc compare) { return (sk_ASN1_TYPE_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }

typedef struct stack_st_ASN1_TYPE ASN1_SEQUENCE_ANY;

ASN1_SEQUENCE_ANY *d2i_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY **a, const unsigned char **in, long len); int i2d_ASN1_SEQUENCE_ANY(const ASN1_SEQUENCE_ANY *a, unsigned char **out); extern const ASN1_ITEM ASN1_SEQUENCE_ANY_it;
ASN1_SEQUENCE_ANY *d2i_ASN1_SET_ANY(ASN1_SEQUENCE_ANY **a, const unsigned char **in, long len); int i2d_ASN1_SET_ANY(const ASN1_SEQUENCE_ANY *a, unsigned char **out); extern const ASN1_ITEM ASN1_SET_ANY_it;


typedef struct BIT_STRING_BITNAME_st {
    int bitnum;
    const char *lname;
    const char *sname;
} BIT_STRING_BITNAME;
# 518 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
ASN1_TYPE *ASN1_TYPE_new(void); void ASN1_TYPE_free(ASN1_TYPE *a); ASN1_TYPE *d2i_ASN1_TYPE(ASN1_TYPE **a, const unsigned char **in, long len); int i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **out); extern const ASN1_ITEM ASN1_ANY_it;

int ASN1_TYPE_get(const ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b);

ASN1_TYPE *ASN1_TYPE_pack_sequence(const ASN1_ITEM *it, void *s, ASN1_TYPE **t);
void *ASN1_TYPE_unpack_sequence(const ASN1_ITEM *it, const ASN1_TYPE *t);

ASN1_OBJECT *ASN1_OBJECT_new(void);
void ASN1_OBJECT_free(ASN1_OBJECT *a);
int i2d_ASN1_OBJECT(const ASN1_OBJECT *a, unsigned char **pp);
ASN1_OBJECT *d2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp,
                             long length);

extern const ASN1_ITEM ASN1_OBJECT_it;

struct stack_st_ASN1_OBJECT; typedef int (*sk_ASN1_OBJECT_compfunc)(const ASN1_OBJECT * const *a, const ASN1_OBJECT *const *b); typedef void (*sk_ASN1_OBJECT_freefunc)(ASN1_OBJECT *a); typedef ASN1_OBJECT * (*sk_ASN1_OBJECT_copyfunc)(const ASN1_OBJECT *a); static __attribute__((unused)) inline int sk_ASN1_OBJECT_num(const struct stack_st_ASN1_OBJECT *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_OBJECT *sk_ASN1_OBJECT_value(const struct stack_st_ASN1_OBJECT *sk, int idx) { return (ASN1_OBJECT *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static __attribute__((unused)) inline struct stack_st_ASN1_OBJECT *sk_ASN1_OBJECT_new(sk_ASN1_OBJECT_compfunc compare) { return (struct stack_st_ASN1_OBJECT *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); } static __attribute__((unused)) inline struct stack_st_ASN1_OBJECT *sk_ASN1_OBJECT_new_null(void) { return (struct stack_st_ASN1_OBJECT *)OPENSSL_sk_new_null(); } static __attribute__((unused)) inline struct stack_st_ASN1_OBJECT *sk_ASN1_OBJECT_new_reserve(sk_ASN1_OBJECT_compfunc compare, int n) { return (struct stack_st_ASN1_OBJECT *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); } static __attribute__((unused)) inline int sk_ASN1_OBJECT_reserve(struct stack_st_ASN1_OBJECT *sk, int n) { return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); } static __attribute__((unused)) inline void sk_ASN1_OBJECT_free(struct stack_st_ASN1_OBJECT *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_OBJECT_zero(struct stack_st_ASN1_OBJECT *sk) { OPENSSL_sk_zero((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_OBJECT *sk_ASN1_OBJECT_delete(struct stack_st_ASN1_OBJECT *sk, int i) { return (ASN1_OBJECT *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); } static __attribute__((unused)) inline ASN1_OBJECT *sk_ASN1_OBJECT_delete_ptr(struct stack_st_ASN1_OBJECT *sk, ASN1_OBJECT *ptr) { return (ASN1_OBJECT *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_OBJECT_push(struct stack_st_ASN1_OBJECT *sk, ASN1_OBJECT *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_OBJECT_unshift(struct stack_st_ASN1_OBJECT *sk, ASN1_OBJECT *ptr) { return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline ASN1_OBJECT *sk_ASN1_OBJECT_pop(struct stack_st_ASN1_OBJECT *sk) { return (ASN1_OBJECT *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline ASN1_OBJECT *sk_ASN1_OBJECT_shift(struct stack_st_ASN1_OBJECT *sk) { return (ASN1_OBJECT *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline void sk_ASN1_OBJECT_pop_free(struct stack_st_ASN1_OBJECT *sk, sk_ASN1_OBJECT_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline int sk_ASN1_OBJECT_insert(struct stack_st_ASN1_OBJECT *sk, ASN1_OBJECT *ptr, int idx) { return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); } static __attribute__((unused)) inline ASN1_OBJECT *sk_ASN1_OBJECT_set(struct stack_st_ASN1_OBJECT *sk, int idx, ASN1_OBJECT *ptr) { return (ASN1_OBJECT *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_OBJECT_find(struct stack_st_ASN1_OBJECT *sk, ASN1_OBJECT *ptr) { return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline int sk_ASN1_OBJECT_find_ex(struct stack_st_ASN1_OBJECT *sk, ASN1_OBJECT *ptr) { return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); } static __attribute__((unused)) inline void sk_ASN1_OBJECT_sort(struct stack_st_ASN1_OBJECT *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); } static __attribute__((unused)) inline int sk_ASN1_OBJECT_is_sorted(const struct stack_st_ASN1_OBJECT *sk) { return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_OBJECT * sk_ASN1_OBJECT_dup(const struct stack_st_ASN1_OBJECT *sk) { return (struct stack_st_ASN1_OBJECT *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); } static __attribute__((unused)) inline struct stack_st_ASN1_OBJECT *sk_ASN1_OBJECT_deep_copy(const struct stack_st_ASN1_OBJECT *sk, sk_ASN1_OBJECT_copyfunc copyfunc, sk_ASN1_OBJECT_freefunc freefunc) { return (struct stack_st_ASN1_OBJECT *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc); } static __attribute__((unused)) inline sk_ASN1_OBJECT_compfunc sk_ASN1_OBJECT_set_cmp_func(struct stack_st_ASN1_OBJECT *sk, sk_ASN1_OBJECT_compfunc compare) { return (sk_ASN1_OBJECT_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); }

ASN1_STRING *ASN1_STRING_new(void);
void ASN1_STRING_free(ASN1_STRING *a);
void ASN1_STRING_clear_free(ASN1_STRING *a);
int ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str);
ASN1_STRING *ASN1_STRING_dup(const ASN1_STRING *a);
ASN1_STRING *ASN1_STRING_type_new(int type);
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);




int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
int ASN1_STRING_length(const ASN1_STRING *x);
void ASN1_STRING_length_set(ASN1_STRING *x, int n);
int ASN1_STRING_type(const ASN1_STRING *x);
unsigned char *ASN1_STRING_data(ASN1_STRING *x) __attribute__ ((deprecated));
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);

ASN1_BIT_STRING *ASN1_BIT_STRING_new(void); void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a); ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const unsigned char **in, long len); int i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BIT_STRING_it;
int ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d, int length);
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int ASN1_BIT_STRING_get_bit(const ASN1_BIT_STRING *a, int n);
int ASN1_BIT_STRING_check(const ASN1_BIT_STRING *a,
                          const unsigned char *flags, int flags_len);

int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
                               BIT_STRING_BITNAME *tbl, int indent);
int ASN1_BIT_STRING_num_asc(const char *name, BIT_STRING_BITNAME *tbl);
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, const char *name, int value,
                            BIT_STRING_BITNAME *tbl);

ASN1_INTEGER *ASN1_INTEGER_new(void); void ASN1_INTEGER_free(ASN1_INTEGER *a); ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **in, long len); int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out); extern const ASN1_ITEM ASN1_INTEGER_it;
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a, const unsigned char **pp,
                                long length);
ASN1_INTEGER *ASN1_INTEGER_dup(const ASN1_INTEGER *x);
int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y);

ASN1_ENUMERATED *ASN1_ENUMERATED_new(void); void ASN1_ENUMERATED_free(ASN1_ENUMERATED *a); ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a, const unsigned char **in, long len); int i2d_ASN1_ENUMERATED(ASN1_ENUMERATED *a, unsigned char **out); extern const ASN1_ITEM ASN1_ENUMERATED_it;

int ASN1_UTCTIME_check(const ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t);
ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
                               int offset_day, long offset_sec);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);

int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
                                               time_t t);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s,
                                               time_t t, int offset_day,
                                               long offset_sec);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);

int ASN1_TIME_diff(int *pday, int *psec,
                   const ASN1_TIME *from, const ASN1_TIME *to);

ASN1_OCTET_STRING *ASN1_OCTET_STRING_new(void); void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a); ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a, const unsigned char **in, long len); int i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_OCTET_STRING_it;
ASN1_OCTET_STRING *ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *a);
int ASN1_OCTET_STRING_cmp(const ASN1_OCTET_STRING *a,
                          const ASN1_OCTET_STRING *b);
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data,
                          int len);

ASN1_VISIBLESTRING *ASN1_VISIBLESTRING_new(void); void ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *a); ASN1_VISIBLESTRING *d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_VISIBLESTRING_it;
ASN1_UNIVERSALSTRING *ASN1_UNIVERSALSTRING_new(void); void ASN1_UNIVERSALSTRING_free(ASN1_UNIVERSALSTRING *a); ASN1_UNIVERSALSTRING *d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UNIVERSALSTRING_it;
ASN1_UTF8STRING *ASN1_UTF8STRING_new(void); void ASN1_UTF8STRING_free(ASN1_UTF8STRING *a); ASN1_UTF8STRING *d2i_ASN1_UTF8STRING(ASN1_UTF8STRING **a, const unsigned char **in, long len); int i2d_ASN1_UTF8STRING(ASN1_UTF8STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTF8STRING_it;
ASN1_NULL *ASN1_NULL_new(void); void ASN1_NULL_free(ASN1_NULL *a); ASN1_NULL *d2i_ASN1_NULL(ASN1_NULL **a, const unsigned char **in, long len); int i2d_ASN1_NULL(ASN1_NULL *a, unsigned char **out); extern const ASN1_ITEM ASN1_NULL_it;
ASN1_BMPSTRING *ASN1_BMPSTRING_new(void); void ASN1_BMPSTRING_free(ASN1_BMPSTRING *a); ASN1_BMPSTRING *d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a, const unsigned char **in, long len); int i2d_ASN1_BMPSTRING(ASN1_BMPSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BMPSTRING_it;

int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);

ASN1_STRING *ASN1_PRINTABLE_new(void); void ASN1_PRINTABLE_free(ASN1_STRING *a); ASN1_STRING *d2i_ASN1_PRINTABLE(ASN1_STRING **a, const unsigned char **in, long len); int i2d_ASN1_PRINTABLE(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_PRINTABLE_it;

ASN1_STRING *DIRECTORYSTRING_new(void); void DIRECTORYSTRING_free(ASN1_STRING *a); ASN1_STRING *d2i_DIRECTORYSTRING(ASN1_STRING **a, const unsigned char **in, long len); int i2d_DIRECTORYSTRING(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM DIRECTORYSTRING_it;
ASN1_STRING *DISPLAYTEXT_new(void); void DISPLAYTEXT_free(ASN1_STRING *a); ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, const unsigned char **in, long len); int i2d_DISPLAYTEXT(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM DISPLAYTEXT_it;
ASN1_PRINTABLESTRING *ASN1_PRINTABLESTRING_new(void); void ASN1_PRINTABLESTRING_free(ASN1_PRINTABLESTRING *a); ASN1_PRINTABLESTRING *d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_PRINTABLESTRING_it;
ASN1_T61STRING *ASN1_T61STRING_new(void); void ASN1_T61STRING_free(ASN1_T61STRING *a); ASN1_T61STRING *d2i_ASN1_T61STRING(ASN1_T61STRING **a, const unsigned char **in, long len); int i2d_ASN1_T61STRING(ASN1_T61STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_T61STRING_it;
ASN1_IA5STRING *ASN1_IA5STRING_new(void); void ASN1_IA5STRING_free(ASN1_IA5STRING *a); ASN1_IA5STRING *d2i_ASN1_IA5STRING(ASN1_IA5STRING **a, const unsigned char **in, long len); int i2d_ASN1_IA5STRING(ASN1_IA5STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_IA5STRING_it;
ASN1_GENERALSTRING *ASN1_GENERALSTRING_new(void); void ASN1_GENERALSTRING_free(ASN1_GENERALSTRING *a); ASN1_GENERALSTRING *d2i_ASN1_GENERALSTRING(ASN1_GENERALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_GENERALSTRING(ASN1_GENERALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_GENERALSTRING_it;
ASN1_UTCTIME *ASN1_UTCTIME_new(void); void ASN1_UTCTIME_free(ASN1_UTCTIME *a); ASN1_UTCTIME *d2i_ASN1_UTCTIME(ASN1_UTCTIME **a, const unsigned char **in, long len); int i2d_ASN1_UTCTIME(ASN1_UTCTIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTCTIME_it;
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_new(void); void ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *a); ASN1_GENERALIZEDTIME *d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **a, const unsigned char **in, long len); int i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_GENERALIZEDTIME_it;
ASN1_TIME *ASN1_TIME_new(void); void ASN1_TIME_free(ASN1_TIME *a); ASN1_TIME *d2i_ASN1_TIME(ASN1_TIME **a, const unsigned char **in, long len); int i2d_ASN1_TIME(ASN1_TIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_TIME_it;

extern const ASN1_ITEM ASN1_OCTET_STRING_NDEF_it;

ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t);
ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s, time_t t,
                         int offset_day, long offset_sec);
int ASN1_TIME_check(const ASN1_TIME *t);
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(const ASN1_TIME *t,
                                                   ASN1_GENERALIZEDTIME **out);
int ASN1_TIME_set_string(ASN1_TIME *s, const char *str);
int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str);
int ASN1_TIME_to_tm(const ASN1_TIME *s, struct tm *tm);
int ASN1_TIME_normalize(ASN1_TIME *s);
int ASN1_TIME_cmp_time_t(const ASN1_TIME *s, time_t t);
int ASN1_TIME_compare(const ASN1_TIME *a, const ASN1_TIME *b);

int i2a_ASN1_INTEGER(BIO *bp, const ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *bs, char *buf, int size);
int i2a_ASN1_ENUMERATED(BIO *bp, const ASN1_ENUMERATED *a);
int a2i_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *bs, char *buf, int size);
int i2a_ASN1_OBJECT(BIO *bp, const ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp, ASN1_STRING *bs, char *buf, int size);
int i2a_ASN1_STRING(BIO *bp, const ASN1_STRING *a, int type);
int i2t_ASN1_OBJECT(char *buf, int buf_len, const ASN1_OBJECT *a);

int a2d_ASN1_OBJECT(unsigned char *out, int olen, const char *buf, int num);
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data, int len,
                                const char *sn, const char *ln);

int ASN1_INTEGER_get_int64(int64_t *pr, const ASN1_INTEGER *a);
int ASN1_INTEGER_set_int64(ASN1_INTEGER *a, int64_t r);
int ASN1_INTEGER_get_uint64(uint64_t *pr, const ASN1_INTEGER *a);
int ASN1_INTEGER_set_uint64(ASN1_INTEGER *a, uint64_t r);

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(const ASN1_INTEGER *a);
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);

int ASN1_ENUMERATED_get_int64(int64_t *pr, const ASN1_ENUMERATED *a);
int ASN1_ENUMERATED_set_int64(ASN1_ENUMERATED *a, int64_t r);


int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
long ASN1_ENUMERATED_get(const ASN1_ENUMERATED *a);
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(const BIGNUM *bn, ASN1_ENUMERATED *ai);
BIGNUM *ASN1_ENUMERATED_to_BN(const ASN1_ENUMERATED *ai, BIGNUM *bn);



int ASN1_PRINTABLE_type(const unsigned char *s, int max);

unsigned long ASN1_tag2bit(int tag);


int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
                    int *pclass, long omax);
int ASN1_check_infinite_end(unsigned char **p, long len);
int ASN1_const_check_infinite_end(const unsigned char **p, long len);
void ASN1_put_object(unsigned char **pp, int constructed, int length,
                     int tag, int xclass);
int ASN1_put_eoc(unsigned char **pp);
int ASN1_object_size(int constructed, int length, int tag);


void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);
# 700 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
void *ASN1_item_dup(const ASN1_ITEM *it, void *x);
# 734 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
int ASN1_STRING_to_UTF8(unsigned char **out, const ASN1_STRING *in);

void *ASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x);







void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x);
int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, unsigned char *x);
# 757 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, void *x);
int ASN1_UTCTIME_print(BIO *fp, const ASN1_UTCTIME *a);
int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a);
int ASN1_TIME_print(BIO *fp, const ASN1_TIME *a);
int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v);
int ASN1_STRING_print_ex(BIO *out, const ASN1_STRING *str, unsigned long flags);
int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int off);
int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
                  unsigned char *buf, int off);
int ASN1_parse(BIO *bp, const unsigned char *pp, long len, int indent);
int ASN1_parse_dump(BIO *bp, const unsigned char *pp, long len, int indent,
                    int dump);
const char *ASN1_tag2str(int tag);



int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);

int ASN1_TYPE_set_octetstring(ASN1_TYPE *a, unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(const ASN1_TYPE *a, unsigned char *data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
                                  unsigned char *data, int len);
int ASN1_TYPE_get_int_octetstring(const ASN1_TYPE *a, long *num,
                                  unsigned char *data, int max_len);

void *ASN1_item_unpack(const ASN1_STRING *oct, const ASN1_ITEM *it);

ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it,
                            ASN1_OCTET_STRING **oct);

void ASN1_STRING_set_default_mask(unsigned long mask);
int ASN1_STRING_set_default_mask_asc(const char *p);
unsigned long ASN1_STRING_get_default_mask(void);
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
                       int inform, unsigned long mask);
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
                        int inform, unsigned long mask,
                        long minsize, long maxsize);

ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
                                    const unsigned char *in, int inlen,
                                    int inform, int nid);
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void ASN1_STRING_TABLE_cleanup(void);




ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);
ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in,
                          long len, const ASN1_ITEM *it);
int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
int ASN1_item_ndef_i2d(ASN1_VALUE *val, unsigned char **out,
                       const ASN1_ITEM *it);

void ASN1_add_oid_module(void);
void ASN1_add_stable_module(void);

ASN1_TYPE *ASN1_generate_nconf(const char *str, CONF *nconf);
ASN1_TYPE *ASN1_generate_v3(const char *str, X509V3_CTX *cnf);
int ASN1_str2mask(const char *str, unsigned long *pmask);
# 842 "../intel-sgx-ssl/Linux/package/include/openssl/asn1.h"
int ASN1_item_print(BIO *out, ASN1_VALUE *ifld, int indent,
                    const ASN1_ITEM *it, const ASN1_PCTX *pctx);
ASN1_PCTX *ASN1_PCTX_new(void);
void ASN1_PCTX_free(ASN1_PCTX *p);
unsigned long ASN1_PCTX_get_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_nm_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_cert_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_oid_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_str_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags);

ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb) (ASN1_SCTX *ctx));
void ASN1_SCTX_free(ASN1_SCTX *p);
const ASN1_ITEM *ASN1_SCTX_get_item(ASN1_SCTX *p);
const ASN1_TEMPLATE *ASN1_SCTX_get_template(ASN1_SCTX *p);
unsigned long ASN1_SCTX_get_flags(ASN1_SCTX *p);
void ASN1_SCTX_set_app_data(ASN1_SCTX *p, void *data);
void *ASN1_SCTX_get_app_data(ASN1_SCTX *p);

const BIO_METHOD *BIO_f_asn1(void);

BIO *BIO_new_NDEF(BIO *out, ASN1_VALUE *val, const ASN1_ITEM *it);

int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
                        const ASN1_ITEM *it);
int PEM_write_bio_ASN1_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
                              const char *hdr, const ASN1_ITEM *it);
int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
                     int ctype_nid, int econt_nid,
                     struct stack_st_X509_ALGOR *mdalgs, const ASN1_ITEM *it);
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);

const ASN1_ITEM *ASN1_ITEM_lookup(const char *name);
const ASN1_ITEM *ASN1_ITEM_get(size_t i);
# 18 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h" 2




# 1 "../intel-sgx-ssl/Linux/package/include/openssl/ecerr.h" 1
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/ecerr.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h" 1
# 15 "../intel-sgx-ssl/Linux/package/include/openssl/ecerr.h" 2






int ERR_load_EC_strings(void);
# 23 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h" 2
# 33 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
typedef enum {


    POINT_CONVERSION_COMPRESSED = 2,

    POINT_CONVERSION_UNCOMPRESSED = 4,


    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef struct ec_method_st EC_METHOD;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_point_st EC_POINT;
typedef struct ecpk_parameters_st ECPKPARAMETERS;
typedef struct ec_parameters_st ECPARAMETERS;
# 58 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
const EC_METHOD *EC_GFp_simple_method(void);




const EC_METHOD *EC_GFp_mont_method(void);




const EC_METHOD *EC_GFp_nist_method(void);
# 107 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);




void EC_GROUP_free(EC_GROUP *group);




void EC_GROUP_clear_free(EC_GROUP *group);






int EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src);






EC_GROUP *EC_GROUP_dup(const EC_GROUP *src);





const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group);





int EC_METHOD_get_field_type(const EC_METHOD *meth);
# 153 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
                           const BIGNUM *order, const BIGNUM *cofactor);





const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);





BN_MONT_CTX *EC_GROUP_get_mont_data(const EC_GROUP *group);







int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);





const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group);





int EC_GROUP_order_bits(const EC_GROUP *group);







int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor,
                          BN_CTX *ctx);





const BIGNUM *EC_GROUP_get0_cofactor(const EC_GROUP *group);





void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);





int EC_GROUP_get_curve_name(const EC_GROUP *group);

void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *group);

void EC_GROUP_set_point_conversion_form(EC_GROUP *group,
                                        point_conversion_form_t form);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);

unsigned char *EC_GROUP_get0_seed(const EC_GROUP *x);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
# 236 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_GROUP_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                       const BIGNUM *b, BN_CTX *ctx);
# 249 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_GROUP_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b,
                       BN_CTX *ctx);
# 261 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
# 274 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
# 309 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_GROUP_get_degree(const EC_GROUP *group);






int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);






int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx);







int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);
# 346 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a,
                                 const BIGNUM *b, BN_CTX *ctx);
# 366 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);






EC_GROUP *EC_GROUP_new_from_ecparameters(const ECPARAMETERS *params);







ECPARAMETERS *EC_GROUP_get_ecparameters(const EC_GROUP *group,
                                        ECPARAMETERS *params);






EC_GROUP *EC_GROUP_new_from_ecpkparameters(const ECPKPARAMETERS *params);







ECPKPARAMETERS *EC_GROUP_get_ecpkparameters(const EC_GROUP *group,
                                            ECPKPARAMETERS *params);





typedef struct {
    int nid;
    const char *comment;
} EC_builtin_curve;







size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

const char *EC_curve_nid2nist(int nid);
int EC_curve_nist2nid(const char *name);
# 428 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_POINT *EC_POINT_new(const EC_GROUP *group);




void EC_POINT_free(EC_POINT *point);




void EC_POINT_clear_free(EC_POINT *point);






int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);







EC_POINT *EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group);





const EC_METHOD *EC_POINT_method_of(const EC_POINT *point);






int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);
# 477 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             EC_POINT *p, const BIGNUM *x,
                                             const BIGNUM *y, const BIGNUM *z,
                                             BN_CTX *ctx);
# 491 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             const EC_POINT *p, BIGNUM *x,
                                             BIGNUM *y, BIGNUM *z,
                                             BN_CTX *ctx);
# 504 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p,
                                    const BIGNUM *x, const BIGNUM *y,
                                    BN_CTX *ctx);
# 516 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p,
                                    BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
# 528 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
# 543 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
# 557 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_set_compressed_coordinates(const EC_GROUP *group, EC_POINT *p,
                                        const BIGNUM *x, int y_bit,
                                        BN_CTX *ctx);
# 570 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, int y_bit, BN_CTX *ctx);
# 631 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p,
                          point_conversion_form_t form,
                          unsigned char *buf, size_t len, BN_CTX *ctx);
# 643 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p,
                       const unsigned char *buf, size_t len, BN_CTX *ctx);
# 654 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
                          point_conversion_form_t form,
                          unsigned char **pbuf, BN_CTX *ctx);


BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
                          point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
                            EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
                         point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
                             EC_POINT *, BN_CTX *);
# 680 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 const EC_POINT *b, BN_CTX *ctx);
# 690 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 BN_CTX *ctx);







int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);






int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *p);







int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
                         BN_CTX *ctx);
# 724 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b,
                 BN_CTX *ctx);

int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx);
int EC_POINTs_make_affine(const EC_GROUP *group, size_t num,
                          EC_POINT *points[], BN_CTX *ctx);
# 741 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
                  size_t num, const EC_POINT *p[], const BIGNUM *m[],
                  BN_CTX *ctx);
# 754 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
                 const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);






int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx);





int EC_GROUP_have_precompute_mult(const EC_GROUP *group);





extern const ASN1_ITEM ECPKPARAMETERS_it;
ECPKPARAMETERS *ECPKPARAMETERS_new(void); void ECPKPARAMETERS_free(ECPKPARAMETERS *a);
extern const ASN1_ITEM ECPARAMETERS_it;
ECPARAMETERS *ECPARAMETERS_new(void); void ECPARAMETERS_free(ECPARAMETERS *a);





int EC_GROUP_get_basis_type(const EC_GROUP *);
# 793 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);
# 803 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off);
# 824 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_KEY *EC_KEY_new(void);

int EC_KEY_get_flags(const EC_KEY *key);

void EC_KEY_set_flags(EC_KEY *key, int flags);

void EC_KEY_clear_flags(EC_KEY *key, int flags);






EC_KEY *EC_KEY_new_by_curve_name(int nid);




void EC_KEY_free(EC_KEY *key);






EC_KEY *EC_KEY_copy(EC_KEY *dst, const EC_KEY *src);





EC_KEY *EC_KEY_dup(const EC_KEY *src);





int EC_KEY_up_ref(EC_KEY *key);





ENGINE *EC_KEY_get0_engine(const EC_KEY *eckey);





const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);







int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);





const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key);







int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);





const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);







int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);

unsigned EC_KEY_get_enc_flags(const EC_KEY *key);
void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);
void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform);



int EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg);
void *EC_KEY_get_ex_data(const EC_KEY *key, int idx);


void EC_KEY_set_asn1_flag(EC_KEY *eckey, int asn1_flag);







int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx);





int EC_KEY_generate_key(EC_KEY *key);





int EC_KEY_check_key(const EC_KEY *key);





int EC_KEY_can_sign(const EC_KEY *eckey);
# 957 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x,
                                             BIGNUM *y);
# 967 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form,
                      unsigned char **pbuf, BN_CTX *ctx);
# 978 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf, size_t len,
                   BN_CTX *ctx);
# 988 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int EC_KEY_oct2priv(EC_KEY *key, const unsigned char *buf, size_t len);
# 998 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
size_t EC_KEY_priv2oct(const EC_KEY *key, unsigned char *buf, size_t len);






size_t EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf);
# 1017 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_KEY *d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len);







int i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);
# 1038 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_KEY *d2i_ECParameters(EC_KEY **key, const unsigned char **in, long len);







int i2d_ECParameters(EC_KEY *key, unsigned char **out);
# 1060 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len);







int i2o_ECPublicKey(const EC_KEY *key, unsigned char **out);






int ECParameters_print(BIO *bp, const EC_KEY *key);







int EC_KEY_print(BIO *bp, const EC_KEY *key, int off);
# 1103 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
const EC_KEY_METHOD *EC_KEY_OpenSSL(void);
const EC_KEY_METHOD *EC_KEY_get_default_method(void);
void EC_KEY_set_default_method(const EC_KEY_METHOD *meth);
const EC_KEY_METHOD *EC_KEY_get_method(const EC_KEY *key);
int EC_KEY_set_method(EC_KEY *key, const EC_KEY_METHOD *meth);
EC_KEY *EC_KEY_new_method(ENGINE *engine);






int ECDH_KDF_X9_62(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const unsigned char *sinfo, size_t sinfolen,
                   const EVP_MD *md);

int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                     const EC_KEY *ecdh,
                     void *(*KDF) (const void *in, size_t inlen,
                                   void *out, size_t *outlen));

typedef struct ECDSA_SIG_st ECDSA_SIG;




ECDSA_SIG *ECDSA_SIG_new(void);




void ECDSA_SIG_free(ECDSA_SIG *sig);







int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp);
# 1152 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len);






void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);




const BIGNUM *ECDSA_SIG_get0_r(const ECDSA_SIG *sig);




const BIGNUM *ECDSA_SIG_get0_s(const ECDSA_SIG *sig);






int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
# 1185 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len,
                         EC_KEY *eckey);
# 1198 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen,
                            const BIGNUM *kinv, const BIGNUM *rp,
                            EC_KEY *eckey);
# 1211 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey);
# 1221 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **rp);
# 1233 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen,
               unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
# 1249 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen,
                  unsigned char *sig, unsigned int *siglen,
                  const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);
# 1264 "../intel-sgx-ssl/Linux/package/include/openssl/ec.h"
int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen,
                 const unsigned char *sig, int siglen, EC_KEY *eckey);





int ECDSA_size(const EC_KEY *eckey);





EC_KEY_METHOD *EC_KEY_METHOD_new(const EC_KEY_METHOD *meth);
void EC_KEY_METHOD_free(EC_KEY_METHOD *meth);
void EC_KEY_METHOD_set_init(EC_KEY_METHOD *meth,
                            int (*init)(EC_KEY *key),
                            void (*finish)(EC_KEY *key),
                            int (*copy)(EC_KEY *dest, const EC_KEY *src),
                            int (*set_group)(EC_KEY *key, const EC_GROUP *grp),
                            int (*set_private)(EC_KEY *key,
                                               const BIGNUM *priv_key),
                            int (*set_public)(EC_KEY *key,
                                              const EC_POINT *pub_key));

void EC_KEY_METHOD_set_keygen(EC_KEY_METHOD *meth,
                              int (*keygen)(EC_KEY *key));

void EC_KEY_METHOD_set_compute_key(EC_KEY_METHOD *meth,
                                   int (*ckey)(unsigned char **psec,
                                               size_t *pseclen,
                                               const EC_POINT *pub_key,
                                               const EC_KEY *ecdh));

void EC_KEY_METHOD_set_sign(EC_KEY_METHOD *meth,
                            int (*sign)(int type, const unsigned char *dgst,
                                        int dlen, unsigned char *sig,
                                        unsigned int *siglen,
                                        const BIGNUM *kinv, const BIGNUM *r,
                                        EC_KEY *eckey),
                            int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                              BIGNUM **kinvp, BIGNUM **rp),
                            ECDSA_SIG *(*sign_sig)(const unsigned char *dgst,
                                                   int dgst_len,
                                                   const BIGNUM *in_kinv,
                                                   const BIGNUM *in_r,
                                                   EC_KEY *eckey));

void EC_KEY_METHOD_set_verify(EC_KEY_METHOD *meth,
                              int (*verify)(int type, const unsigned
                                            char *dgst, int dgst_len,
                                            const unsigned char *sigbuf,
                                            int sig_len, EC_KEY *eckey),
                              int (*verify_sig)(const unsigned char *dgst,
                                                int dgst_len,
                                                const ECDSA_SIG *sig,
                                                EC_KEY *eckey));

void EC_KEY_METHOD_get_init(const EC_KEY_METHOD *meth,
                            int (**pinit)(EC_KEY *key),
                            void (**pfinish)(EC_KEY *key),
                            int (**pcopy)(EC_KEY *dest, const EC_KEY *src),
                            int (**pset_group)(EC_KEY *key,
                                               const EC_GROUP *grp),
                            int (**pset_private)(EC_KEY *key,
                                                 const BIGNUM *priv_key),
                            int (**pset_public)(EC_KEY *key,
                                                const EC_POINT *pub_key));

void EC_KEY_METHOD_get_keygen(const EC_KEY_METHOD *meth,
                              int (**pkeygen)(EC_KEY *key));

void EC_KEY_METHOD_get_compute_key(const EC_KEY_METHOD *meth,
                                   int (**pck)(unsigned char **psec,
                                               size_t *pseclen,
                                               const EC_POINT *pub_key,
                                               const EC_KEY *ecdh));

void EC_KEY_METHOD_get_sign(const EC_KEY_METHOD *meth,
                            int (**psign)(int type, const unsigned char *dgst,
                                          int dlen, unsigned char *sig,
                                          unsigned int *siglen,
                                          const BIGNUM *kinv, const BIGNUM *r,
                                          EC_KEY *eckey),
                            int (**psign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                                BIGNUM **kinvp, BIGNUM **rp),
                            ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
                                                     int dgst_len,
                                                     const BIGNUM *in_kinv,
                                                     const BIGNUM *in_r,
                                                     EC_KEY *eckey));

void EC_KEY_METHOD_get_verify(const EC_KEY_METHOD *meth,
                              int (**pverify)(int type, const unsigned
                                              char *dgst, int dgst_len,
                                              const unsigned char *sigbuf,
                                              int sig_len, EC_KEY *eckey),
                              int (**pverify_sig)(const unsigned char *dgst,
                                                  int dgst_len,
                                                  const ECDSA_SIG *sig,
                                                  EC_KEY *eckey));
# 10 "../intel-sgx-ssl/Linux/package/include/openssl/ecdsa.h" 2
# 35 "secure_enclave.c" 2


# 1 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h" 1
# 13 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/opensslconf.h" 1
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h" 2



# 1 "../intel-sgx-ssl/Linux/package/include/openssl/evperr.h" 1
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/evperr.h"
int ERR_load_EVP_strings(void);
# 18 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h" 2
# 28 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/objects.h" 1
# 13 "../intel-sgx-ssl/Linux/package/include/openssl/objects.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/obj_mac.h" 1
# 14 "../intel-sgx-ssl/Linux/package/include/openssl/objects.h" 2


# 1 "../intel-sgx-ssl/Linux/package/include/openssl/objectserr.h" 1
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/objectserr.h"
int ERR_load_OBJ_strings(void);
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/objects.h" 2
# 35 "../intel-sgx-ssl/Linux/package/include/openssl/objects.h"
typedef struct obj_name_st {
    int type;
    int alias;
    const char *name;
    const char *data;
} OBJ_NAME;



int OBJ_NAME_init(void);
int OBJ_NAME_new_index(unsigned long (*hash_func) (const char *),
                       int (*cmp_func) (const char *, const char *),
                       void (*free_func) (const char *, int, const char *));
const char *OBJ_NAME_get(const char *name, int type);
int OBJ_NAME_add(const char *name, int type, const char *data);
int OBJ_NAME_remove(const char *name, int type);
void OBJ_NAME_cleanup(int type);
void OBJ_NAME_do_all(int type, void (*fn) (const OBJ_NAME *, void *arg),
                     void *arg);
void OBJ_NAME_do_all_sorted(int type,
                            void (*fn) (const OBJ_NAME *, void *arg),
                            void *arg);

ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *o);
ASN1_OBJECT *OBJ_nid2obj(int n);
const char *OBJ_nid2ln(int n);
const char *OBJ_nid2sn(int n);
int OBJ_obj2nid(const ASN1_OBJECT *o);
ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);
int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
int OBJ_txt2nid(const char *s);
int OBJ_ln2nid(const char *s);
int OBJ_sn2nid(const char *s);
int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b);
const void *OBJ_bsearch_(const void *key, const void *base, int num, int size,
                         int (*cmp) (const void *, const void *));
const void *OBJ_bsearch_ex_(const void *key, const void *base, int num,
                            int size,
                            int (*cmp) (const void *, const void *),
                            int flags);
# 155 "../intel-sgx-ssl/Linux/package/include/openssl/objects.h"
int OBJ_new_nid(int num);
int OBJ_add_object(const ASN1_OBJECT *obj);
int OBJ_create(const char *oid, const char *sn, const char *ln);



int OBJ_create_objects(BIO *in);

size_t OBJ_length(const ASN1_OBJECT *obj);
const unsigned char *OBJ_get0_data(const ASN1_OBJECT *obj);

int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid);
int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid);
int OBJ_add_sigid(int signid, int dig_id, int pkey_id);
void OBJ_sigid_free(void);
# 29 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h" 2
# 76 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type);
EVP_MD *EVP_MD_meth_dup(const EVP_MD *md);
void EVP_MD_meth_free(EVP_MD *md);

int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize);
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize);
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags);
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx));
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count));
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md));
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to,
                                                 const EVP_MD_CTX *from));
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx));
int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2));

int EVP_MD_meth_get_input_blocksize(const EVP_MD *md);
int EVP_MD_meth_get_result_size(const EVP_MD *md);
int EVP_MD_meth_get_app_datasize(const EVP_MD *md);
unsigned long EVP_MD_meth_get_flags(const EVP_MD *md);
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx);
int (*EVP_MD_meth_get_update(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                                const void *data,
                                                size_t count);
int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                               unsigned char *md);
int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
                                              const EVP_MD_CTX *from);
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx);
int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2);
# 185 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);
EVP_CIPHER *EVP_CIPHER_meth_dup(const EVP_CIPHER *cipher);
void EVP_CIPHER_meth_free(EVP_CIPHER *cipher);

int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len);
int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags);
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size);
int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
                             int (*init) (EVP_CIPHER_CTX *ctx,
                                          const unsigned char *key,
                                          const unsigned char *iv,
                                          int enc));
int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
                                  int (*do_cipher) (EVP_CIPHER_CTX *ctx,
                                                    unsigned char *out,
                                                    const unsigned char *in,
                                                    size_t inl));
int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher,
                                int (*cleanup) (EVP_CIPHER_CTX *));
int EVP_CIPHER_meth_set_set_asn1_params(EVP_CIPHER *cipher,
                                        int (*set_asn1_parameters) (EVP_CIPHER_CTX *,
                                                                    ASN1_TYPE *));
int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER *cipher,
                                        int (*get_asn1_parameters) (EVP_CIPHER_CTX *,
                                                                    ASN1_TYPE *));
int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
                             int (*ctrl) (EVP_CIPHER_CTX *, int type,
                                          int arg, void *ptr));

int (*EVP_CIPHER_meth_get_init(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
                                                          const unsigned char *key,
                                                          const unsigned char *iv,
                                                          int enc);
int (*EVP_CIPHER_meth_get_do_cipher(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *ctx,
                                                               unsigned char *out,
                                                               const unsigned char *in,
                                                               size_t inl);
int (*EVP_CIPHER_meth_get_cleanup(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *);
int (*EVP_CIPHER_meth_get_set_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
                                                                     ASN1_TYPE *);
int (*EVP_CIPHER_meth_get_get_asn1_params(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
                                                               ASN1_TYPE *);
int (*EVP_CIPHER_meth_get_ctrl(const EVP_CIPHER *cipher))(EVP_CIPHER_CTX *,
                                                          int type, int arg,
                                                          void *ptr);
# 362 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
typedef struct {
    unsigned char *out;
    const unsigned char *inp;
    size_t len;
    unsigned int interleave;
} EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;
# 392 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
typedef struct evp_cipher_info_st {
    const EVP_CIPHER *cipher;
    unsigned char iv[16];
} EVP_CIPHER_INFO;



typedef int (EVP_PBE_KEYGEN) (EVP_CIPHER_CTX *ctx, const char *pass,
                              int passlen, ASN1_TYPE *param,
                              const EVP_CIPHER *cipher, const EVP_MD *md,
                              int en_de);
# 439 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
int EVP_MD_type(const EVP_MD *md);


int EVP_MD_pkey_type(const EVP_MD *md);
int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
unsigned long EVP_MD_flags(const EVP_MD *md);

const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
int (*EVP_MD_CTX_update_fn(EVP_MD_CTX *ctx))(EVP_MD_CTX *ctx,
                                             const void *data, size_t count);
void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
                              int (*update) (EVP_MD_CTX *ctx,
                                             const void *data, size_t count));



EVP_PKEY_CTX *EVP_MD_CTX_pkey_ctx(const EVP_MD_CTX *ctx);
void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);
void *EVP_MD_CTX_md_data(const EVP_MD_CTX *ctx);

int EVP_CIPHER_nid(const EVP_CIPHER *cipher);

int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher);


const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_num(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data);
# 520 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
           int EVP_Cipher(EVP_CIPHER_CTX *c,
                          unsigned char *out,
                          const unsigned char *in, unsigned int inl);
# 533 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
EVP_MD_CTX *EVP_MD_CTX_new(void);
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);



 int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags);
 int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
                                 ENGINE *impl);
 int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                size_t cnt);
 int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s);
 int EVP_Digest(const void *data, size_t count,
                          unsigned char *md, unsigned int *size,
                          const EVP_MD *type, ENGINE *impl);

 int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);
 int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
 int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md,
                           unsigned int *s);
 int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md,
                              size_t len);

int EVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
int EVP_read_pw_string_min(char *buf, int minlen, int maxlen,
                           const char *prompt, int verify);
void EVP_set_pw_prompt(const char *prompt);
char *EVP_get_pw_prompt(void);

 int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                          const unsigned char *salt,
                          const unsigned char *data, int datal, int count,
                          unsigned char *key, unsigned char *iv);

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags);

 int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
           int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
           int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
           int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   int *outl);
           int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl);

 int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
           int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
           int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
 int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                            int *outl);
           int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl);

 int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                          const unsigned char *key, const unsigned char *iv,
                          int enc);
           int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                                 const EVP_CIPHER *cipher, ENGINE *impl,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc);
 int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl, const unsigned char *in, int inl);
 int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                           int *outl);
 int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                              int *outl);

 int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                         EVP_PKEY *pkey);

 int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
                          size_t *siglen, const unsigned char *tbs,
                          size_t tbslen);

 int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                           unsigned int siglen, EVP_PKEY *pkey);

 int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
                            size_t siglen, const unsigned char *tbs,
                            size_t tbslen);

           int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                  const EVP_MD *type, ENGINE *e,
                                  EVP_PKEY *pkey);
 int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                               size_t *siglen);

 int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                const EVP_MD *type, ENGINE *e,
                                EVP_PKEY *pkey);
 int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen);


 int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        const unsigned char *ek, int ekl,
                        const unsigned char *iv, EVP_PKEY *priv);
 int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

 int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        unsigned char **ek, int *ekl, unsigned char *iv,
                        EVP_PKEY **pubk, int npubk);
 int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);


EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void);
void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx);
int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, EVP_ENCODE_CTX *sctx);
int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx);
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
int EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned
                    char *out, int *outl);
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);





EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);

const BIO_METHOD *BIO_f_md(void);
const BIO_METHOD *BIO_f_base64(void);
const BIO_METHOD *BIO_f_cipher(void);
const BIO_METHOD *BIO_f_reliable(void);
 int BIO_set_cipher(BIO *b, const EVP_CIPHER *c, const unsigned char *k,
                          const unsigned char *i, int enc);

const EVP_MD *EVP_md_null(void);







const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_md5_sha1(void);


const EVP_MD *EVP_blake2b512(void);
const EVP_MD *EVP_blake2s256(void);

const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_sha512_224(void);
const EVP_MD *EVP_sha512_256(void);
const EVP_MD *EVP_sha3_224(void);
const EVP_MD *EVP_sha3_256(void);
const EVP_MD *EVP_sha3_384(void);
const EVP_MD *EVP_sha3_512(void);
const EVP_MD *EVP_shake128(void);
const EVP_MD *EVP_shake256(void);




const EVP_MD *EVP_ripemd160(void);


const EVP_MD *EVP_whirlpool(void);


const EVP_MD *EVP_sm3(void);

const EVP_CIPHER *EVP_enc_null(void);

const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede_ecb(void);
const EVP_CIPHER *EVP_des_ede3_ecb(void);
const EVP_CIPHER *EVP_des_cfb64(void);

const EVP_CIPHER *EVP_des_cfb1(void);
const EVP_CIPHER *EVP_des_cfb8(void);
const EVP_CIPHER *EVP_des_ede_cfb64(void);

const EVP_CIPHER *EVP_des_ede3_cfb64(void);

const EVP_CIPHER *EVP_des_ede3_cfb1(void);
const EVP_CIPHER *EVP_des_ede3_cfb8(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_desx_cbc(void);
const EVP_CIPHER *EVP_des_ede3_wrap(void);
# 776 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
const EVP_CIPHER *EVP_rc2_ecb(void);
const EVP_CIPHER *EVP_rc2_cbc(void);
const EVP_CIPHER *EVP_rc2_40_cbc(void);
const EVP_CIPHER *EVP_rc2_64_cbc(void);
const EVP_CIPHER *EVP_rc2_cfb64(void);

const EVP_CIPHER *EVP_rc2_ofb(void);
# 805 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb1(void);
const EVP_CIPHER *EVP_aes_128_cfb8(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);

const EVP_CIPHER *EVP_aes_128_ofb(void);
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_128_ccm(void);
const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_128_xts(void);
const EVP_CIPHER *EVP_aes_128_wrap(void);
const EVP_CIPHER *EVP_aes_128_wrap_pad(void);

const EVP_CIPHER *EVP_aes_128_ocb(void);

const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_cfb1(void);
const EVP_CIPHER *EVP_aes_192_cfb8(void);
const EVP_CIPHER *EVP_aes_192_cfb128(void);

const EVP_CIPHER *EVP_aes_192_ofb(void);
const EVP_CIPHER *EVP_aes_192_ctr(void);
const EVP_CIPHER *EVP_aes_192_ccm(void);
const EVP_CIPHER *EVP_aes_192_gcm(void);
const EVP_CIPHER *EVP_aes_192_wrap(void);
const EVP_CIPHER *EVP_aes_192_wrap_pad(void);

const EVP_CIPHER *EVP_aes_192_ocb(void);

const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb1(void);
const EVP_CIPHER *EVP_aes_256_cfb8(void);
const EVP_CIPHER *EVP_aes_256_cfb128(void);

const EVP_CIPHER *EVP_aes_256_ofb(void);
const EVP_CIPHER *EVP_aes_256_ctr(void);
const EVP_CIPHER *EVP_aes_256_ccm(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_CIPHER *EVP_aes_256_xts(void);
const EVP_CIPHER *EVP_aes_256_wrap(void);
const EVP_CIPHER *EVP_aes_256_wrap_pad(void);

const EVP_CIPHER *EVP_aes_256_ocb(void);

const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256(void);
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256(void);

const EVP_CIPHER *EVP_aria_128_ecb(void);
const EVP_CIPHER *EVP_aria_128_cbc(void);
const EVP_CIPHER *EVP_aria_128_cfb1(void);
const EVP_CIPHER *EVP_aria_128_cfb8(void);
const EVP_CIPHER *EVP_aria_128_cfb128(void);

const EVP_CIPHER *EVP_aria_128_ctr(void);
const EVP_CIPHER *EVP_aria_128_ofb(void);
const EVP_CIPHER *EVP_aria_128_gcm(void);
const EVP_CIPHER *EVP_aria_128_ccm(void);
const EVP_CIPHER *EVP_aria_192_ecb(void);
const EVP_CIPHER *EVP_aria_192_cbc(void);
const EVP_CIPHER *EVP_aria_192_cfb1(void);
const EVP_CIPHER *EVP_aria_192_cfb8(void);
const EVP_CIPHER *EVP_aria_192_cfb128(void);

const EVP_CIPHER *EVP_aria_192_ctr(void);
const EVP_CIPHER *EVP_aria_192_ofb(void);
const EVP_CIPHER *EVP_aria_192_gcm(void);
const EVP_CIPHER *EVP_aria_192_ccm(void);
const EVP_CIPHER *EVP_aria_256_ecb(void);
const EVP_CIPHER *EVP_aria_256_cbc(void);
const EVP_CIPHER *EVP_aria_256_cfb1(void);
const EVP_CIPHER *EVP_aria_256_cfb8(void);
const EVP_CIPHER *EVP_aria_256_cfb128(void);

const EVP_CIPHER *EVP_aria_256_ctr(void);
const EVP_CIPHER *EVP_aria_256_ofb(void);
const EVP_CIPHER *EVP_aria_256_gcm(void);
const EVP_CIPHER *EVP_aria_256_ccm(void);
# 915 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
const EVP_CIPHER *EVP_chacha20(void);

const EVP_CIPHER *EVP_chacha20_poly1305(void);




const EVP_CIPHER *EVP_seed_ecb(void);
const EVP_CIPHER *EVP_seed_cbc(void);
const EVP_CIPHER *EVP_seed_cfb128(void);

const EVP_CIPHER *EVP_seed_ofb(void);



const EVP_CIPHER *EVP_sm4_ecb(void);
const EVP_CIPHER *EVP_sm4_cbc(void);
const EVP_CIPHER *EVP_sm4_cfb128(void);

const EVP_CIPHER *EVP_sm4_ofb(void);
const EVP_CIPHER *EVP_sm4_ctr(void);
# 961 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
int EVP_add_cipher(const EVP_CIPHER *cipher);
int EVP_add_digest(const EVP_MD *digest);

const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
const EVP_MD *EVP_get_digestbyname(const char *name);

void EVP_CIPHER_do_all(void (*fn) (const EVP_CIPHER *ciph,
                                   const char *from, const char *to, void *x),
                       void *arg);
void EVP_CIPHER_do_all_sorted(void (*fn)
                               (const EVP_CIPHER *ciph, const char *from,
                                const char *to, void *x), void *arg);

void EVP_MD_do_all(void (*fn) (const EVP_MD *ciph,
                               const char *from, const char *to, void *x),
                   void *arg);
void EVP_MD_do_all_sorted(void (*fn)
                           (const EVP_MD *ciph, const char *from,
                            const char *to, void *x), void *arg);

int EVP_PKEY_decrypt_old(unsigned char *dec_key,
                         const unsigned char *enc_key, int enc_key_len,
                         EVP_PKEY *private_key);
int EVP_PKEY_encrypt_old(unsigned char *enc_key,
                         const unsigned char *key, int key_len,
                         EVP_PKEY *pub_key);
int EVP_PKEY_type(int type);
int EVP_PKEY_id(const EVP_PKEY *pkey);
int EVP_PKEY_base_id(const EVP_PKEY *pkey);
int EVP_PKEY_bits(const EVP_PKEY *pkey);
int EVP_PKEY_security_bits(const EVP_PKEY *pkey);
int EVP_PKEY_size(const EVP_PKEY *pkey);
int EVP_PKEY_set_type(EVP_PKEY *pkey, int type);
int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len);
int EVP_PKEY_set_alias_type(EVP_PKEY *pkey, int type);

int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e);

int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
void *EVP_PKEY_get0(const EVP_PKEY *pkey);
const unsigned char *EVP_PKEY_get0_hmac(const EVP_PKEY *pkey, size_t *len);

const unsigned char *EVP_PKEY_get0_poly1305(const EVP_PKEY *pkey, size_t *len);


const unsigned char *EVP_PKEY_get0_siphash(const EVP_PKEY *pkey, size_t *len);



struct rsa_st;
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
struct rsa_st *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);


struct dsa_st;
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, struct dsa_st *key);
struct dsa_st *EVP_PKEY_get0_DSA(EVP_PKEY *pkey);
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);


struct dh_st;
int EVP_PKEY_set1_DH(EVP_PKEY *pkey, struct dh_st *key);
struct dh_st *EVP_PKEY_get0_DH(EVP_PKEY *pkey);
struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);


struct ec_key_st;
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, struct ec_key_st *key);
struct ec_key_st *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);


EVP_PKEY *EVP_PKEY_new(void);
int EVP_PKEY_up_ref(EVP_PKEY *pkey);
void EVP_PKEY_free(EVP_PKEY *pkey);

EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
                        long length);
int i2d_PublicKey(EVP_PKEY *a, unsigned char **pp);

EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp,
                         long length);
EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
                             long length);
int i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp);

int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
int EVP_PKEY_save_parameters(EVP_PKEY *pkey, int mode);
int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);

int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
                          int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
                           int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
                          int indent, ASN1_PCTX *pctx);

int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid);

int EVP_PKEY_set1_tls_encodedpoint(EVP_PKEY *pkey,
                                   const unsigned char *pt, size_t ptlen);
size_t EVP_PKEY_get1_tls_encodedpoint(EVP_PKEY *pkey, unsigned char **ppt);

int EVP_CIPHER_type(const EVP_CIPHER *ctx);


int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);


int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type);


int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                       ASN1_TYPE *param, const EVP_CIPHER *cipher,
                       const EVP_MD *md, int en_de);
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out);
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVP_MD *digest, int keylen, unsigned char *out);
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                          ASN1_TYPE *param, const EVP_CIPHER *cipher,
                          const EVP_MD *md, int en_de);


int EVP_PBE_scrypt(const char *pass, size_t passlen,
                   const unsigned char *salt, size_t saltlen,
                   uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                   unsigned char *key, size_t keylen);

int PKCS5_v2_scrypt_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, ASN1_TYPE *param,
                             const EVP_CIPHER *c, const EVP_MD *md, int en_de);


void PKCS5_PBE_add(void);

int EVP_PBE_CipherInit(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                       ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de);
# 1117 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
                         int md_nid, EVP_PBE_KEYGEN *keygen);
int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
                    EVP_PBE_KEYGEN *keygen);
int EVP_PBE_find(int type, int pbe_nid, int *pcnid, int *pmnid,
                 EVP_PBE_KEYGEN **pkeygen);
void EVP_PBE_cleanup(void);
int EVP_PBE_get(int *ptype, int *ppbe_nid, size_t num);
# 1140 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
int EVP_PKEY_asn1_get_count(void);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(ENGINE **pe, int type);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find_str(ENGINE **pe,
                                                   const char *str, int len);
int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD *ameth);
int EVP_PKEY_asn1_add_alias(int to, int from);
int EVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id,
                            int *ppkey_flags, const char **pinfo,
                            const char **ppem_str,
                            const EVP_PKEY_ASN1_METHOD *ameth);

const EVP_PKEY_ASN1_METHOD *EVP_PKEY_get0_asn1(const EVP_PKEY *pkey);
EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_new(int id, int flags,
                                        const char *pem_str,
                                        const char *info);
void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD *dst,
                        const EVP_PKEY_ASN1_METHOD *src);
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth,
                              int (*pub_decode) (EVP_PKEY *pk,
                                                 X509_PUBKEY *pub),
                              int (*pub_encode) (X509_PUBKEY *pub,
                                                 const EVP_PKEY *pk),
                              int (*pub_cmp) (const EVP_PKEY *a,
                                              const EVP_PKEY *b),
                              int (*pub_print) (BIO *out,
                                                const EVP_PKEY *pkey,
                                                int indent, ASN1_PCTX *pctx),
                              int (*pkey_size) (const EVP_PKEY *pk),
                              int (*pkey_bits) (const EVP_PKEY *pk));
void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD *ameth,
                               int (*priv_decode) (EVP_PKEY *pk,
                                                   const PKCS8_PRIV_KEY_INFO
                                                   *p8inf),
                               int (*priv_encode) (PKCS8_PRIV_KEY_INFO *p8,
                                                   const EVP_PKEY *pk),
                               int (*priv_print) (BIO *out,
                                                  const EVP_PKEY *pkey,
                                                  int indent,
                                                  ASN1_PCTX *pctx));
void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD *ameth,
                             int (*param_decode) (EVP_PKEY *pkey,
                                                  const unsigned char **pder,
                                                  int derlen),
                             int (*param_encode) (const EVP_PKEY *pkey,
                                                  unsigned char **pder),
                             int (*param_missing) (const EVP_PKEY *pk),
                             int (*param_copy) (EVP_PKEY *to,
                                                const EVP_PKEY *from),
                             int (*param_cmp) (const EVP_PKEY *a,
                                               const EVP_PKEY *b),
                             int (*param_print) (BIO *out,
                                                 const EVP_PKEY *pkey,
                                                 int indent,
                                                 ASN1_PCTX *pctx));

void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth,
                            void (*pkey_free) (EVP_PKEY *pkey));
void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth,
                            int (*pkey_ctrl) (EVP_PKEY *pkey, int op,
                                              long arg1, void *arg2));
void EVP_PKEY_asn1_set_item(EVP_PKEY_ASN1_METHOD *ameth,
                            int (*item_verify) (EVP_MD_CTX *ctx,
                                                const ASN1_ITEM *it,
                                                void *asn,
                                                X509_ALGOR *a,
                                                ASN1_BIT_STRING *sig,
                                                EVP_PKEY *pkey),
                            int (*item_sign) (EVP_MD_CTX *ctx,
                                              const ASN1_ITEM *it,
                                              void *asn,
                                              X509_ALGOR *alg1,
                                              X509_ALGOR *alg2,
                                              ASN1_BIT_STRING *sig));

void EVP_PKEY_asn1_set_siginf(EVP_PKEY_ASN1_METHOD *ameth,
                              int (*siginf_set) (X509_SIG_INFO *siginf,
                                                 const X509_ALGOR *alg,
                                                 const ASN1_STRING *sig));

void EVP_PKEY_asn1_set_check(EVP_PKEY_ASN1_METHOD *ameth,
                             int (*pkey_check) (const EVP_PKEY *pk));

void EVP_PKEY_asn1_set_public_check(EVP_PKEY_ASN1_METHOD *ameth,
                                    int (*pkey_pub_check) (const EVP_PKEY *pk));

void EVP_PKEY_asn1_set_param_check(EVP_PKEY_ASN1_METHOD *ameth,
                                   int (*pkey_param_check) (const EVP_PKEY *pk));

void EVP_PKEY_asn1_set_set_priv_key(EVP_PKEY_ASN1_METHOD *ameth,
                                    int (*set_priv_key) (EVP_PKEY *pk,
                                                         const unsigned char
                                                            *priv,
                                                         size_t len));
void EVP_PKEY_asn1_set_set_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
                                   int (*set_pub_key) (EVP_PKEY *pk,
                                                       const unsigned char *pub,
                                                       size_t len));
void EVP_PKEY_asn1_set_get_priv_key(EVP_PKEY_ASN1_METHOD *ameth,
                                    int (*get_priv_key) (const EVP_PKEY *pk,
                                                         unsigned char *priv,
                                                         size_t *len));
void EVP_PKEY_asn1_set_get_pub_key(EVP_PKEY_ASN1_METHOD *ameth,
                                   int (*get_pub_key) (const EVP_PKEY *pk,
                                                       unsigned char *pub,
                                                       size_t *len));

void EVP_PKEY_asn1_set_security_bits(EVP_PKEY_ASN1_METHOD *ameth,
                                     int (*pkey_security_bits) (const EVP_PKEY
                                                                *pk));
# 1322 "../intel-sgx-ssl/Linux/package/include/openssl/evp.h"
const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type);
EVP_PKEY_METHOD *EVP_PKEY_meth_new(int id, int flags);
void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
                             const EVP_PKEY_METHOD *meth);
void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src);
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth);
int EVP_PKEY_meth_remove(const EVP_PKEY_METHOD *pmeth);
size_t EVP_PKEY_meth_get_count(void);
const EVP_PKEY_METHOD *EVP_PKEY_meth_get0(size_t idx);

EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_dup(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);

int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2);
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                          const char *value);
int EVP_PKEY_CTX_ctrl_uint64(EVP_PKEY_CTX *ctx, int keytype, int optype,
                             int cmd, uint64_t value);

int EVP_PKEY_CTX_str2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *str);
int EVP_PKEY_CTX_hex2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *hex);

int EVP_PKEY_CTX_md(EVP_PKEY_CTX *ctx, int optype, int cmd, const char *md);

int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen);

EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e,
                               const unsigned char *key, int keylen);
EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e,
                                       const unsigned char *priv,
                                       size_t len);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
                                      const unsigned char *pub,
                                      size_t len);
int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv,
                                 size_t *len);
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub,
                                size_t *len);

EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
                                size_t len, const EVP_CIPHER *cipher);

void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data);
void *EVP_PKEY_CTX_get_data(EVP_PKEY_CTX *ctx);
EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);

EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx);

void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data);
void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx);

int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
                  unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,
                            unsigned char *rout, size_t *routlen,
                            const unsigned char *sig, size_t siglen);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);

int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);

int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx);
int EVP_PKEY_param_check(EVP_PKEY_CTX *ctx);

void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb);
EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx);

int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx);

void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
                            int (*init) (EVP_PKEY_CTX *ctx));

void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth,
                            int (*copy) (EVP_PKEY_CTX *dst,
                                         EVP_PKEY_CTX *src));

void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth,
                               void (*cleanup) (EVP_PKEY_CTX *ctx));

void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth,
                                int (*paramgen_init) (EVP_PKEY_CTX *ctx),
                                int (*paramgen) (EVP_PKEY_CTX *ctx,
                                                 EVP_PKEY *pkey));

void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth,
                              int (*keygen_init) (EVP_PKEY_CTX *ctx),
                              int (*keygen) (EVP_PKEY_CTX *ctx,
                                             EVP_PKEY *pkey));

void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth,
                            int (*sign_init) (EVP_PKEY_CTX *ctx),
                            int (*sign) (EVP_PKEY_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs,
                                         size_t tbslen));

void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth,
                              int (*verify_init) (EVP_PKEY_CTX *ctx),
                              int (*verify) (EVP_PKEY_CTX *ctx,
                                             const unsigned char *sig,
                                             size_t siglen,
                                             const unsigned char *tbs,
                                             size_t tbslen));

void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth,
                                      int (*verify_recover_init) (EVP_PKEY_CTX
                                                                  *ctx),
                                      int (*verify_recover) (EVP_PKEY_CTX
                                                             *ctx,
                                                             unsigned char
                                                             *sig,
                                                             size_t *siglen,
                                                             const unsigned
                                                             char *tbs,
                                                             size_t tbslen));

void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth,
                               int (*signctx_init) (EVP_PKEY_CTX *ctx,
                                                    EVP_MD_CTX *mctx),
                               int (*signctx) (EVP_PKEY_CTX *ctx,
                                               unsigned char *sig,
                                               size_t *siglen,
                                               EVP_MD_CTX *mctx));

void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth,
                                 int (*verifyctx_init) (EVP_PKEY_CTX *ctx,
                                                        EVP_MD_CTX *mctx),
                                 int (*verifyctx) (EVP_PKEY_CTX *ctx,
                                                   const unsigned char *sig,
                                                   int siglen,
                                                   EVP_MD_CTX *mctx));

void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth,
                               int (*encrypt_init) (EVP_PKEY_CTX *ctx),
                               int (*encryptfn) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen));

void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth,
                               int (*decrypt_init) (EVP_PKEY_CTX *ctx),
                               int (*decrypt) (EVP_PKEY_CTX *ctx,
                                               unsigned char *out,
                                               size_t *outlen,
                                               const unsigned char *in,
                                               size_t inlen));

void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth,
                              int (*derive_init) (EVP_PKEY_CTX *ctx),
                              int (*derive) (EVP_PKEY_CTX *ctx,
                                             unsigned char *key,
                                             size_t *keylen));

void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth,
                            int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1,
                                         void *p2),
                            int (*ctrl_str) (EVP_PKEY_CTX *ctx,
                                             const char *type,
                                             const char *value));

void EVP_PKEY_meth_set_check(EVP_PKEY_METHOD *pmeth,
                             int (*check) (EVP_PKEY *pkey));

void EVP_PKEY_meth_set_public_check(EVP_PKEY_METHOD *pmeth,
                                    int (*check) (EVP_PKEY *pkey));

void EVP_PKEY_meth_set_param_check(EVP_PKEY_METHOD *pmeth,
                                   int (*check) (EVP_PKEY *pkey));

void EVP_PKEY_meth_set_digest_custom(EVP_PKEY_METHOD *pmeth,
                                     int (*digest_custom) (EVP_PKEY_CTX *ctx,
                                                           EVP_MD_CTX *mctx));

void EVP_PKEY_meth_get_init(const EVP_PKEY_METHOD *pmeth,
                            int (**pinit) (EVP_PKEY_CTX *ctx));

void EVP_PKEY_meth_get_copy(const EVP_PKEY_METHOD *pmeth,
                            int (**pcopy) (EVP_PKEY_CTX *dst,
                                           EVP_PKEY_CTX *src));

void EVP_PKEY_meth_get_cleanup(const EVP_PKEY_METHOD *pmeth,
                               void (**pcleanup) (EVP_PKEY_CTX *ctx));

void EVP_PKEY_meth_get_paramgen(const EVP_PKEY_METHOD *pmeth,
                                int (**pparamgen_init) (EVP_PKEY_CTX *ctx),
                                int (**pparamgen) (EVP_PKEY_CTX *ctx,
                                                   EVP_PKEY *pkey));

void EVP_PKEY_meth_get_keygen(const EVP_PKEY_METHOD *pmeth,
                              int (**pkeygen_init) (EVP_PKEY_CTX *ctx),
                              int (**pkeygen) (EVP_PKEY_CTX *ctx,
                                               EVP_PKEY *pkey));

void EVP_PKEY_meth_get_sign(const EVP_PKEY_METHOD *pmeth,
                            int (**psign_init) (EVP_PKEY_CTX *ctx),
                            int (**psign) (EVP_PKEY_CTX *ctx,
                                           unsigned char *sig, size_t *siglen,
                                           const unsigned char *tbs,
                                           size_t tbslen));

void EVP_PKEY_meth_get_verify(const EVP_PKEY_METHOD *pmeth,
                              int (**pverify_init) (EVP_PKEY_CTX *ctx),
                              int (**pverify) (EVP_PKEY_CTX *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen));

void EVP_PKEY_meth_get_verify_recover(const EVP_PKEY_METHOD *pmeth,
                                      int (**pverify_recover_init) (EVP_PKEY_CTX
                                                                    *ctx),
                                      int (**pverify_recover) (EVP_PKEY_CTX
                                                               *ctx,
                                                               unsigned char
                                                               *sig,
                                                               size_t *siglen,
                                                               const unsigned
                                                               char *tbs,
                                                               size_t tbslen));

void EVP_PKEY_meth_get_signctx(const EVP_PKEY_METHOD *pmeth,
                               int (**psignctx_init) (EVP_PKEY_CTX *ctx,
                                                      EVP_MD_CTX *mctx),
                               int (**psignctx) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *sig,
                                                 size_t *siglen,
                                                 EVP_MD_CTX *mctx));

void EVP_PKEY_meth_get_verifyctx(const EVP_PKEY_METHOD *pmeth,
                                 int (**pverifyctx_init) (EVP_PKEY_CTX *ctx,
                                                          EVP_MD_CTX *mctx),
                                 int (**pverifyctx) (EVP_PKEY_CTX *ctx,
                                                     const unsigned char *sig,
                                                     int siglen,
                                                     EVP_MD_CTX *mctx));

void EVP_PKEY_meth_get_encrypt(const EVP_PKEY_METHOD *pmeth,
                               int (**pencrypt_init) (EVP_PKEY_CTX *ctx),
                               int (**pencryptfn) (EVP_PKEY_CTX *ctx,
                                                   unsigned char *out,
                                                   size_t *outlen,
                                                   const unsigned char *in,
                                                   size_t inlen));

void EVP_PKEY_meth_get_decrypt(const EVP_PKEY_METHOD *pmeth,
                               int (**pdecrypt_init) (EVP_PKEY_CTX *ctx),
                               int (**pdecrypt) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen));

void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD *pmeth,
                              int (**pderive_init) (EVP_PKEY_CTX *ctx),
                              int (**pderive) (EVP_PKEY_CTX *ctx,
                                               unsigned char *key,
                                               size_t *keylen));

void EVP_PKEY_meth_get_ctrl(const EVP_PKEY_METHOD *pmeth,
                            int (**pctrl) (EVP_PKEY_CTX *ctx, int type, int p1,
                                           void *p2),
                            int (**pctrl_str) (EVP_PKEY_CTX *ctx,
                                               const char *type,
                                               const char *value));

void EVP_PKEY_meth_get_check(const EVP_PKEY_METHOD *pmeth,
                             int (**pcheck) (EVP_PKEY *pkey));

void EVP_PKEY_meth_get_public_check(const EVP_PKEY_METHOD *pmeth,
                                    int (**pcheck) (EVP_PKEY *pkey));

void EVP_PKEY_meth_get_param_check(const EVP_PKEY_METHOD *pmeth,
                                   int (**pcheck) (EVP_PKEY *pkey));

void EVP_PKEY_meth_get_digest_custom(EVP_PKEY_METHOD *pmeth,
                                     int (**pdigest_custom) (EVP_PKEY_CTX *ctx,
                                                             EVP_MD_CTX *mctx));
void EVP_add_alg_module(void);
# 38 "secure_enclave.c" 2
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/err.h" 1
# 22 "../intel-sgx-ssl/Linux/package/include/openssl/err.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/lhash.h" 1
# 24 "../intel-sgx-ssl/Linux/package/include/openssl/lhash.h"
typedef struct lhash_node_st OPENSSL_LH_NODE;
typedef int (*OPENSSL_LH_COMPFUNC) (const void *, const void *);
typedef unsigned long (*OPENSSL_LH_HASHFUNC) (const void *);
typedef void (*OPENSSL_LH_DOALL_FUNC) (void *);
typedef void (*OPENSSL_LH_DOALL_FUNCARG) (void *, void *);
typedef struct lhash_st OPENSSL_LHASH;
# 72 "../intel-sgx-ssl/Linux/package/include/openssl/lhash.h"
int OPENSSL_LH_error(OPENSSL_LHASH *lh);
OPENSSL_LHASH *OPENSSL_LH_new(OPENSSL_LH_HASHFUNC h, OPENSSL_LH_COMPFUNC c);
void OPENSSL_LH_free(OPENSSL_LHASH *lh);
void *OPENSSL_LH_insert(OPENSSL_LHASH *lh, void *data);
void *OPENSSL_LH_delete(OPENSSL_LHASH *lh, const void *data);
void *OPENSSL_LH_retrieve(OPENSSL_LHASH *lh, const void *data);
void OPENSSL_LH_doall(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNC func);
void OPENSSL_LH_doall_arg(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNCARG func, void *arg);
unsigned long OPENSSL_LH_strhash(const char *c);
unsigned long OPENSSL_LH_num_items(const OPENSSL_LHASH *lh);
unsigned long OPENSSL_LH_get_down_load(const OPENSSL_LHASH *lh);
void OPENSSL_LH_set_down_load(OPENSSL_LHASH *lh, unsigned long down_load);






void OPENSSL_LH_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
void OPENSSL_LH_node_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
void OPENSSL_LH_node_usage_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
# 197 "../intel-sgx-ssl/Linux/package/include/openssl/lhash.h"
struct lhash_st_OPENSSL_STRING { union lh_OPENSSL_STRING_dummy { void* d1; unsigned long d2; int d3; } dummy; }; static inline struct lhash_st_OPENSSL_STRING * lh_OPENSSL_STRING_new(unsigned long (*hfn)(const OPENSSL_STRING *), int (*cfn)(const OPENSSL_STRING *, const OPENSSL_STRING *)) { return (struct lhash_st_OPENSSL_STRING *) OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn); } static __attribute__((unused)) inline void lh_OPENSSL_STRING_free(struct lhash_st_OPENSSL_STRING *lh) { OPENSSL_LH_free((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline OPENSSL_STRING *lh_OPENSSL_STRING_insert(struct lhash_st_OPENSSL_STRING *lh, OPENSSL_STRING *d) { return (OPENSSL_STRING *)OPENSSL_LH_insert((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline OPENSSL_STRING *lh_OPENSSL_STRING_delete(struct lhash_st_OPENSSL_STRING *lh, const OPENSSL_STRING *d) { return (OPENSSL_STRING *)OPENSSL_LH_delete((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline OPENSSL_STRING *lh_OPENSSL_STRING_retrieve(struct lhash_st_OPENSSL_STRING *lh, const OPENSSL_STRING *d) { return (OPENSSL_STRING *)OPENSSL_LH_retrieve((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline int lh_OPENSSL_STRING_error(struct lhash_st_OPENSSL_STRING *lh) { return OPENSSL_LH_error((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline unsigned long lh_OPENSSL_STRING_num_items(struct lhash_st_OPENSSL_STRING *lh) { return OPENSSL_LH_num_items((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline void lh_OPENSSL_STRING_node_stats_bio(const struct lhash_st_OPENSSL_STRING *lh, BIO *out) { OPENSSL_LH_node_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline void lh_OPENSSL_STRING_node_usage_stats_bio(const struct lhash_st_OPENSSL_STRING *lh, BIO *out) { OPENSSL_LH_node_usage_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline void lh_OPENSSL_STRING_stats_bio(const struct lhash_st_OPENSSL_STRING *lh, BIO *out) { OPENSSL_LH_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline unsigned long lh_OPENSSL_STRING_get_down_load(struct lhash_st_OPENSSL_STRING *lh) { return OPENSSL_LH_get_down_load((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline void lh_OPENSSL_STRING_set_down_load(struct lhash_st_OPENSSL_STRING *lh, unsigned long dl) { OPENSSL_LH_set_down_load((OPENSSL_LHASH *)lh, dl); } static __attribute__((unused)) inline void lh_OPENSSL_STRING_doall(struct lhash_st_OPENSSL_STRING *lh, void (*doall)(OPENSSL_STRING *)) { OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); } struct lhash_st_OPENSSL_STRING;
# 207 "../intel-sgx-ssl/Linux/package/include/openssl/lhash.h"
struct lhash_st_OPENSSL_CSTRING { union lh_OPENSSL_CSTRING_dummy { void* d1; unsigned long d2; int d3; } dummy; }; static inline struct lhash_st_OPENSSL_CSTRING * lh_OPENSSL_CSTRING_new(unsigned long (*hfn)(const OPENSSL_CSTRING *), int (*cfn)(const OPENSSL_CSTRING *, const OPENSSL_CSTRING *)) { return (struct lhash_st_OPENSSL_CSTRING *) OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn); } static __attribute__((unused)) inline void lh_OPENSSL_CSTRING_free(struct lhash_st_OPENSSL_CSTRING *lh) { OPENSSL_LH_free((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline OPENSSL_CSTRING *lh_OPENSSL_CSTRING_insert(struct lhash_st_OPENSSL_CSTRING *lh, OPENSSL_CSTRING *d) { return (OPENSSL_CSTRING *)OPENSSL_LH_insert((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline OPENSSL_CSTRING *lh_OPENSSL_CSTRING_delete(struct lhash_st_OPENSSL_CSTRING *lh, const OPENSSL_CSTRING *d) { return (OPENSSL_CSTRING *)OPENSSL_LH_delete((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline OPENSSL_CSTRING *lh_OPENSSL_CSTRING_retrieve(struct lhash_st_OPENSSL_CSTRING *lh, const OPENSSL_CSTRING *d) { return (OPENSSL_CSTRING *)OPENSSL_LH_retrieve((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline int lh_OPENSSL_CSTRING_error(struct lhash_st_OPENSSL_CSTRING *lh) { return OPENSSL_LH_error((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline unsigned long lh_OPENSSL_CSTRING_num_items(struct lhash_st_OPENSSL_CSTRING *lh) { return OPENSSL_LH_num_items((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline void lh_OPENSSL_CSTRING_node_stats_bio(const struct lhash_st_OPENSSL_CSTRING *lh, BIO *out) { OPENSSL_LH_node_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline void lh_OPENSSL_CSTRING_node_usage_stats_bio(const struct lhash_st_OPENSSL_CSTRING *lh, BIO *out) { OPENSSL_LH_node_usage_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline void lh_OPENSSL_CSTRING_stats_bio(const struct lhash_st_OPENSSL_CSTRING *lh, BIO *out) { OPENSSL_LH_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline unsigned long lh_OPENSSL_CSTRING_get_down_load(struct lhash_st_OPENSSL_CSTRING *lh) { return OPENSSL_LH_get_down_load((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline void lh_OPENSSL_CSTRING_set_down_load(struct lhash_st_OPENSSL_CSTRING *lh, unsigned long dl) { OPENSSL_LH_set_down_load((OPENSSL_LHASH *)lh, dl); } static __attribute__((unused)) inline void lh_OPENSSL_CSTRING_doall(struct lhash_st_OPENSSL_CSTRING *lh, void (*doall)(OPENSSL_CSTRING *)) { OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); } struct lhash_st_OPENSSL_CSTRING;
# 23 "../intel-sgx-ssl/Linux/package/include/openssl/err.h" 2
# 34 "../intel-sgx-ssl/Linux/package/include/openssl/err.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/errno.h" 1
# 179 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/errno.h"



int * __errno(void);



# 35 "../intel-sgx-ssl/Linux/package/include/openssl/err.h" 2







typedef struct err_state_st {
    int err_flags[16];
    unsigned long err_buffer[16];
    char *err_data[16];
    int err_data_flags[16];
    const char *err_file[16];
    int err_line[16];
    int top, bottom;
} ERR_STATE;
# 212 "../intel-sgx-ssl/Linux/package/include/openssl/err.h"
typedef struct ERR_string_data_st {
    unsigned long error;
    const char *string;
} ERR_STRING_DATA;

struct lhash_st_ERR_STRING_DATA { union lh_ERR_STRING_DATA_dummy { void* d1; unsigned long d2; int d3; } dummy; }; static inline struct lhash_st_ERR_STRING_DATA * lh_ERR_STRING_DATA_new(unsigned long (*hfn)(const ERR_STRING_DATA *), int (*cfn)(const ERR_STRING_DATA *, const ERR_STRING_DATA *)) { return (struct lhash_st_ERR_STRING_DATA *) OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn); } static __attribute__((unused)) inline void lh_ERR_STRING_DATA_free(struct lhash_st_ERR_STRING_DATA *lh) { OPENSSL_LH_free((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline ERR_STRING_DATA *lh_ERR_STRING_DATA_insert(struct lhash_st_ERR_STRING_DATA *lh, ERR_STRING_DATA *d) { return (ERR_STRING_DATA *)OPENSSL_LH_insert((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline ERR_STRING_DATA *lh_ERR_STRING_DATA_delete(struct lhash_st_ERR_STRING_DATA *lh, const ERR_STRING_DATA *d) { return (ERR_STRING_DATA *)OPENSSL_LH_delete((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline ERR_STRING_DATA *lh_ERR_STRING_DATA_retrieve(struct lhash_st_ERR_STRING_DATA *lh, const ERR_STRING_DATA *d) { return (ERR_STRING_DATA *)OPENSSL_LH_retrieve((OPENSSL_LHASH *)lh, d); } static __attribute__((unused)) inline int lh_ERR_STRING_DATA_error(struct lhash_st_ERR_STRING_DATA *lh) { return OPENSSL_LH_error((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline unsigned long lh_ERR_STRING_DATA_num_items(struct lhash_st_ERR_STRING_DATA *lh) { return OPENSSL_LH_num_items((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline void lh_ERR_STRING_DATA_node_stats_bio(const struct lhash_st_ERR_STRING_DATA *lh, BIO *out) { OPENSSL_LH_node_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline void lh_ERR_STRING_DATA_node_usage_stats_bio(const struct lhash_st_ERR_STRING_DATA *lh, BIO *out) { OPENSSL_LH_node_usage_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline void lh_ERR_STRING_DATA_stats_bio(const struct lhash_st_ERR_STRING_DATA *lh, BIO *out) { OPENSSL_LH_stats_bio((const OPENSSL_LHASH *)lh, out); } static __attribute__((unused)) inline unsigned long lh_ERR_STRING_DATA_get_down_load(struct lhash_st_ERR_STRING_DATA *lh) { return OPENSSL_LH_get_down_load((OPENSSL_LHASH *)lh); } static __attribute__((unused)) inline void lh_ERR_STRING_DATA_set_down_load(struct lhash_st_ERR_STRING_DATA *lh, unsigned long dl) { OPENSSL_LH_set_down_load((OPENSSL_LHASH *)lh, dl); } static __attribute__((unused)) inline void lh_ERR_STRING_DATA_doall(struct lhash_st_ERR_STRING_DATA *lh, void (*doall)(ERR_STRING_DATA *)) { OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); } struct lhash_st_ERR_STRING_DATA;

void ERR_put_error(int lib, int func, int reason, const char *file, int line);
void ERR_set_error_data(char *data, int flags);

unsigned long ERR_get_error(void);
unsigned long ERR_get_error_line(const char **file, int *line);
unsigned long ERR_get_error_line_data(const char **file, int *line,
                                      const char **data, int *flags);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_error_line(const char **file, int *line);
unsigned long ERR_peek_error_line_data(const char **file, int *line,
                                       const char **data, int *flags);
unsigned long ERR_peek_last_error(void);
unsigned long ERR_peek_last_error_line(const char **file, int *line);
unsigned long ERR_peek_last_error_line_data(const char **file, int *line,
                                            const char **data, int *flags);
void ERR_clear_error(void);
char *ERR_error_string(unsigned long e, char *buf);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
const char *ERR_lib_error_string(unsigned long e);
const char *ERR_func_error_string(unsigned long e);
const char *ERR_reason_error_string(unsigned long e);
void ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u);



void ERR_print_errors(BIO *bp);
void ERR_add_error_data(int num, ...);
void ERR_add_error_vdata(int num, va_list args);
int ERR_load_strings(int lib, ERR_STRING_DATA *str);
int ERR_load_strings_const(const ERR_STRING_DATA *str);
int ERR_unload_strings(int lib, ERR_STRING_DATA *str);
int ERR_load_ERR_strings(void);







void ERR_remove_thread_state(void *) __attribute__ ((deprecated));
void ERR_remove_state(unsigned long pid) __attribute__ ((deprecated));
ERR_STATE *ERR_get_state(void);

int ERR_get_next_error_library(void);

int ERR_set_mark(void);
int ERR_pop_to_mark(void);
int ERR_clear_last_mark(void);
# 39 "secure_enclave.c" 2
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/rand.h" 1
# 16 "../intel-sgx-ssl/Linux/package/include/openssl/rand.h"
# 1 "../intel-sgx-ssl/Linux/package/include/openssl/randerr.h" 1
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/randerr.h"
int ERR_load_RAND_strings(void);
# 17 "../intel-sgx-ssl/Linux/package/include/openssl/rand.h" 2





struct rand_meth_st {
    int (*seed) (const void *buf, int num);
    int (*bytes) (unsigned char *buf, int num);
    void (*cleanup) (void);
    int (*add) (const void *buf, int num, double randomness);
    int (*pseudorand) (unsigned char *buf, int num);
    int (*status) (void);
};

int RAND_set_rand_method(const RAND_METHOD *meth);
const RAND_METHOD *RAND_get_rand_method(void);

int RAND_set_rand_engine(ENGINE *engine);


RAND_METHOD *RAND_OpenSSL(void);




int RAND_bytes(unsigned char *buf, int num);
int RAND_priv_bytes(unsigned char *buf, int num);
int RAND_pseudo_bytes(unsigned char *buf, int num) __attribute__ ((deprecated));

void RAND_seed(const void *buf, int num);
void RAND_keep_random_devices_open(int keep);




void RAND_add(const void *buf, int num, double randomness);
int RAND_load_file(const char *file, long max_bytes);
int RAND_write_file(const char *file);
const char *RAND_file_name(char *file, size_t num);
int RAND_status(void);







int RAND_poll(void);
# 40 "secure_enclave.c" 2
# 1 "../intel-sgx-ssl/Linux/package/include/tSgxSSL_api.h" 1
# 41 "../intel-sgx-ssl/Linux/package/include/tSgxSSL_api.h"
typedef enum {
 STREAM_STDOUT = 1,
 STREAM_STDERR
} Stream_t;

typedef int (*PRINT_TO_STDOUT_STDERR_CB)(Stream_t stream, const char* fmt, va_list);






void SGXSSLSetPrintToStdoutStderrCB(PRINT_TO_STDOUT_STDERR_CB cb);

typedef enum {
 UNREACH_CODE_ABORT_ENCLAVE = 0,
 UNREACH_CODE_REPORT_ERR_AND_CONTNUE = 1,
} UnreachableCodePolicy_t;







void SGXSSLSetUnreachableCodePolicy(UnreachableCodePolicy_t policy);




const char * SGXSSLGetSgxSSLVersion();
# 41 "secure_enclave.c" 2

# 1 "secure_enclave_t.h" 1



# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdint.h" 1
# 5 "secure_enclave_t.h" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/wchar.h" 1
# 84 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/wchar.h"
typedef __mbstate_t mbstate_t;




typedef __wint_t wint_t;
# 101 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/wchar.h"


wint_t btowc(int);
int wctob(wint_t);
size_t mbrlen(const char *, size_t, mbstate_t *);
size_t mbrtowc(wchar_t *, const char *, size_t, mbstate_t *);
int mbsinit(const mbstate_t *);
size_t mbsrtowcs(wchar_t *, const char **, size_t, mbstate_t *);
size_t wcrtomb(char *, wchar_t, mbstate_t *);
wchar_t * wcschr(const wchar_t *, wchar_t);
int wcscmp(const wchar_t *, const wchar_t *);
int wcscoll(const wchar_t *, const wchar_t *);
size_t wcscspn(const wchar_t *, const wchar_t *);
size_t wcslen(const wchar_t *);
wchar_t * wcsncat(wchar_t *, const wchar_t *, size_t);
int wcsncmp(const wchar_t *, const wchar_t *, size_t);
wchar_t * wcsncpy(wchar_t *, const wchar_t *, size_t);
wchar_t * wcspbrk(const wchar_t *, const wchar_t *);
wchar_t * wcsrchr(const wchar_t *, wchar_t);
size_t wcsrtombs(char *, const wchar_t **, size_t, mbstate_t *);
size_t wcsspn(const wchar_t *, const wchar_t *);
wchar_t * wcsstr(const wchar_t *, const wchar_t *);
wchar_t * wcstok(wchar_t *, const wchar_t *, wchar_t **);
size_t wcsxfrm(wchar_t *, const wchar_t *, size_t);
wchar_t * wmemchr(const wchar_t *, wchar_t, size_t);
int wmemcmp(const wchar_t *, const wchar_t *, size_t);
wchar_t * wmemcpy(wchar_t *, const wchar_t *, size_t);
wchar_t * wmemmove(wchar_t *, const wchar_t *, size_t);
wchar_t * wmemset(wchar_t *, wchar_t, size_t);

int swprintf(wchar_t *, size_t, const wchar_t *, ...);
int vswprintf(wchar_t *, size_t, const wchar_t *, __va_list);


wchar_t * wcswcs(const wchar_t *, const wchar_t *);


# 6 "secure_enclave_t.h" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stddef.h" 1
# 43 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stddef.h"
typedef __ptrdiff_t ptrdiff_t;
# 7 "secure_enclave_t.h" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_edger8r.h" 1
# 46 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_edger8r.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_defs.h" 1
# 47 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_edger8r.h" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_error.h" 1
# 37 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_error.h"
typedef enum _status_t
{
    SGX_SUCCESS = (0x00000000|(0x0000)),

    SGX_ERROR_UNEXPECTED = (0x00000000|(0x0001)),
    SGX_ERROR_INVALID_PARAMETER = (0x00000000|(0x0002)),
    SGX_ERROR_OUT_OF_MEMORY = (0x00000000|(0x0003)),
    SGX_ERROR_ENCLAVE_LOST = (0x00000000|(0x0004)),
    SGX_ERROR_INVALID_STATE = (0x00000000|(0x0005)),
    SGX_ERROR_FEATURE_NOT_SUPPORTED = (0x00000000|(0x0008)),



    SGX_ERROR_INVALID_FUNCTION = (0x00000000|(0x1001)),
    SGX_ERROR_OUT_OF_TCS = (0x00000000|(0x1003)),
    SGX_ERROR_ENCLAVE_CRASHED = (0x00000000|(0x1006)),
    SGX_ERROR_ECALL_NOT_ALLOWED = (0x00000000|(0x1007)),
    SGX_ERROR_OCALL_NOT_ALLOWED = (0x00000000|(0x1008)),
    SGX_ERROR_STACK_OVERRUN = (0x00000000|(0x1009)),

    SGX_ERROR_UNDEFINED_SYMBOL = (0x00000000|(0x2000)),
    SGX_ERROR_INVALID_ENCLAVE = (0x00000000|(0x2001)),
    SGX_ERROR_INVALID_ENCLAVE_ID = (0x00000000|(0x2002)),
    SGX_ERROR_INVALID_SIGNATURE = (0x00000000|(0x2003)),
    SGX_ERROR_NDEBUG_ENCLAVE = (0x00000000|(0x2004)),
    SGX_ERROR_OUT_OF_EPC = (0x00000000|(0x2005)),
    SGX_ERROR_NO_DEVICE = (0x00000000|(0x2006)),
    SGX_ERROR_MEMORY_MAP_CONFLICT= (0x00000000|(0x2007)),
    SGX_ERROR_INVALID_METADATA = (0x00000000|(0x2009)),
    SGX_ERROR_DEVICE_BUSY = (0x00000000|(0x200c)),
    SGX_ERROR_INVALID_VERSION = (0x00000000|(0x200d)),
    SGX_ERROR_MODE_INCOMPATIBLE = (0x00000000|(0x200e)),
    SGX_ERROR_ENCLAVE_FILE_ACCESS = (0x00000000|(0x200f)),
    SGX_ERROR_INVALID_MISC = (0x00000000|(0x2010)),
    SGX_ERROR_INVALID_LAUNCH_TOKEN = (0x00000000|(0x2011)),

    SGX_ERROR_MAC_MISMATCH = (0x00000000|(0x3001)),
    SGX_ERROR_INVALID_ATTRIBUTE = (0x00000000|(0x3002)),
    SGX_ERROR_INVALID_CPUSVN = (0x00000000|(0x3003)),
    SGX_ERROR_INVALID_ISVSVN = (0x00000000|(0x3004)),
    SGX_ERROR_INVALID_KEYNAME = (0x00000000|(0x3005)),

    SGX_ERROR_SERVICE_UNAVAILABLE = (0x00000000|(0x4001)),
    SGX_ERROR_SERVICE_TIMEOUT = (0x00000000|(0x4002)),
    SGX_ERROR_AE_INVALID_EPIDBLOB = (0x00000000|(0x4003)),
    SGX_ERROR_SERVICE_INVALID_PRIVILEGE = (0x00000000|(0x4004)),
    SGX_ERROR_EPID_MEMBER_REVOKED = (0x00000000|(0x4005)),
    SGX_ERROR_UPDATE_NEEDED = (0x00000000|(0x4006)),
    SGX_ERROR_NETWORK_FAILURE = (0x00000000|(0x4007)),
    SGX_ERROR_AE_SESSION_INVALID = (0x00000000|(0x4008)),
    SGX_ERROR_BUSY = (0x00000000|(0x400a)),
    SGX_ERROR_MC_NOT_FOUND = (0x00000000|(0x400c)),
    SGX_ERROR_MC_NO_ACCESS_RIGHT = (0x00000000|(0x400d)),
    SGX_ERROR_MC_USED_UP = (0x00000000|(0x400e)),
    SGX_ERROR_MC_OVER_QUOTA = (0x00000000|(0x400f)),
    SGX_ERROR_KDF_MISMATCH = (0x00000000|(0x4011)),
    SGX_ERROR_UNRECOGNIZED_PLATFORM = (0x00000000|(0x4012)),

    SGX_ERROR_NO_PRIVILEGE = (0x00000000|(0x5002)),


    SGX_ERROR_PCL_ENCRYPTED = (0x00000000|(0x6001)),
    SGX_ERROR_PCL_NOT_ENCRYPTED = (0x00000000|(0x6002)),
    SGX_ERROR_PCL_MAC_MISMATCH = (0x00000000|(0x6003)),
    SGX_ERROR_PCL_SHA_MISMATCH = (0x00000000|(0x6004)),
    SGX_ERROR_PCL_GUID_MISMATCH = (0x00000000|(0x6005)),


    SGX_ERROR_FILE_BAD_STATUS = (0x00000000|(0x7001)),
    SGX_ERROR_FILE_NO_KEY_ID = (0x00000000|(0x7002)),
    SGX_ERROR_FILE_NAME_MISMATCH = (0x00000000|(0x7003)),
    SGX_ERROR_FILE_NOT_SGX_FILE = (0x00000000|(0x7004)),
    SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE = (0x00000000|(0x7005)),
    SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE = (0x00000000|(0x7006)),
    SGX_ERROR_FILE_RECOVERY_NEEDED = (0x00000000|(0x7007)),
    SGX_ERROR_FILE_FLUSH_FAILED = (0x00000000|(0x7008)),
    SGX_ERROR_FILE_CLOSE_FAILED = (0x00000000|(0x7009)),


    SGX_ERROR_UNSUPPORTED_ATT_KEY_ID = (0x00000000|(0x8001)),
    SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE = (0x00000000|(0x8002)),
    SGX_ERROR_ATT_KEY_UNINITIALIZED = (0x00000000|(0x8003)),
    SGX_ERROR_INVALID_ATT_KEY_CERT_DATA = (0x00000000|(0x8004)),

    SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED = (0x00000000|(0xF001)),

} sgx_status_t;
# 48 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_edger8r.h" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_eid.h" 1
# 37 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_eid.h"
typedef uint64_t sgx_enclave_id_t;
# 49 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_edger8r.h" 2
# 69 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_edger8r.h"
void* sgx_ocalloc(size_t size);
void* sgx_ocalloc_switchless(size_t size);







void sgx_ocfree(void);
void sgx_ocfree_switchless(void);
# 90 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_edger8r.h"
sgx_status_t sgx_ecall(const sgx_enclave_id_t eid,
                              const int index,
                              const void* ocall_table,
                              void* ms);
sgx_status_t sgx_ecall_switchless(const sgx_enclave_id_t eid,
                              const int index,
                              const void* ocall_table,
                              void* ms);
# 106 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_edger8r.h"
sgx_status_t sgx_ocall(const unsigned int index,
                              void* ms);
sgx_status_t sgx_ocall_switchless(const unsigned int index,
                              void* ms);
# 8 "secure_enclave_t.h" 2

# 1 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h" 1
# 142 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
typedef unsigned long int mp_limb_t;
typedef long int mp_limb_signed_t;


typedef unsigned long int mp_bitcnt_t;




typedef struct
{
  int _mp_alloc;

  int _mp_size;


  mp_limb_t *_mp_d;
} __mpz_struct;




typedef __mpz_struct MP_INT;
typedef __mpz_struct mpz_t[1];

typedef mp_limb_t * mp_ptr;
typedef const mp_limb_t * mp_srcptr;







typedef long int mp_size_t;
typedef long int mp_exp_t;


typedef struct
{
  __mpz_struct _mp_num;
  __mpz_struct _mp_den;
} __mpq_struct;

typedef __mpq_struct MP_RAT;
typedef __mpq_struct mpq_t[1];

typedef struct
{
  int _mp_prec;



  int _mp_size;


  mp_exp_t _mp_exp;
  mp_limb_t *_mp_d;
} __mpf_struct;


typedef __mpf_struct mpf_t[1];


typedef enum
{
  GMP_RAND_ALG_DEFAULT = 0,
  GMP_RAND_ALG_LC = GMP_RAND_ALG_DEFAULT
} gmp_randalg_t;


typedef struct
{
  mpz_t _mp_seed;
  gmp_randalg_t _mp_alg;
  union {
    void *_mp_lc;
  } _mp_algdata;
} __gmp_randstate_struct;
typedef __gmp_randstate_struct gmp_randstate_t[1];



typedef const __mpz_struct *mpz_srcptr;
typedef __mpz_struct *mpz_ptr;
typedef const __mpf_struct *mpf_srcptr;
typedef __mpf_struct *mpf_ptr;
typedef const __mpq_struct *mpq_srcptr;
typedef __mpq_struct *mpq_ptr;
# 473 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmp_set_memory_functions (void *(*) (size_t),
          void *(*) (void *, size_t, size_t),
          void (*) (void *, size_t)) ;


 void __gmp_get_memory_functions (void *(**) (size_t),
          void *(**) (void *, size_t, size_t),
          void (**) (void *, size_t)) ;


 extern const int __gmp_bits_per_limb;


 extern int __gmp_errno;


 extern const char * const __gmp_version;






 void __gmp_randinit (gmp_randstate_t, gmp_randalg_t, ...);


 void __gmp_randinit_default (gmp_randstate_t);


 void __gmp_randinit_lc_2exp (gmp_randstate_t, mpz_srcptr, unsigned long int, mp_bitcnt_t);


 int __gmp_randinit_lc_2exp_size (gmp_randstate_t, mp_bitcnt_t);


 void __gmp_randinit_mt (gmp_randstate_t);


 void __gmp_randinit_set (gmp_randstate_t, const __gmp_randstate_struct *);


 void __gmp_randseed (gmp_randstate_t, mpz_srcptr);


 void __gmp_randseed_ui (gmp_randstate_t, unsigned long int);


 void __gmp_randclear (gmp_randstate_t);


 unsigned long __gmp_urandomb_ui (gmp_randstate_t, unsigned long);


 unsigned long __gmp_urandomm_ui (gmp_randstate_t, unsigned long);





 int __gmp_asprintf (char **, const char *, ...);
# 550 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 int __gmp_printf (const char *, ...);


 int __gmp_snprintf (char *, size_t, const char *, ...);


 int __gmp_sprintf (char *, const char *, ...);



 int __gmp_vasprintf (char **, const char *, va_list);
# 570 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 int __gmp_vprintf (const char *, va_list);




 int __gmp_vsnprintf (char *, size_t, const char *, va_list);




 int __gmp_vsprintf (char *, const char *, va_list);
# 592 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 int __gmp_scanf (const char *, ...);


 int __gmp_sscanf (const char *, const char *, ...);
# 604 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 int __gmp_vscanf (const char *, va_list);




 int __gmp_vsscanf (const char *, const char *, va_list);







 void *__gmpz_realloc (mpz_ptr, mp_size_t);



 void __gmpz_abs (mpz_ptr, mpz_srcptr);



 void __gmpz_add (mpz_ptr, mpz_srcptr, mpz_srcptr);
# 634 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpz_addmul (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_addmul_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_and (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_array_init (mpz_ptr, mp_size_t, mp_size_t);


 void __gmpz_bin_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_bin_uiui (mpz_ptr, unsigned long int, unsigned long int);


 void __gmpz_cdiv_q (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_cdiv_q_2exp (mpz_ptr, mpz_srcptr, mp_bitcnt_t);


 unsigned long int __gmpz_cdiv_q_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_cdiv_qr (mpz_ptr, mpz_ptr, mpz_srcptr, mpz_srcptr);


 unsigned long int __gmpz_cdiv_qr_ui (mpz_ptr, mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_cdiv_r (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_cdiv_r_2exp (mpz_ptr, mpz_srcptr, mp_bitcnt_t);


 unsigned long int __gmpz_cdiv_r_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 unsigned long int __gmpz_cdiv_ui (mpz_srcptr, unsigned long int) __attribute__ ((__pure__));
# 685 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpz_clears (mpz_ptr, ...);


 void __gmpz_clrbit (mpz_ptr, mp_bitcnt_t);


 int __gmpz_cmp (mpz_srcptr, mpz_srcptr) __attribute__ ((__pure__));


 int __gmpz_cmp_d (mpz_srcptr, double) __attribute__ ((__pure__));


 int __gmpz_cmp_si (mpz_srcptr, signed long int) __attribute__ ((__pure__));


 int __gmpz_cmp_ui (mpz_srcptr, unsigned long int) __attribute__ ((__pure__));


 int __gmpz_cmpabs (mpz_srcptr, mpz_srcptr) __attribute__ ((__pure__));


 int __gmpz_cmpabs_d (mpz_srcptr, double) __attribute__ ((__pure__));


 int __gmpz_cmpabs_ui (mpz_srcptr, unsigned long int) __attribute__ ((__pure__));


 void __gmpz_com (mpz_ptr, mpz_srcptr);


 void __gmpz_combit (mpz_ptr, mp_bitcnt_t);


 int __gmpz_congruent_p (mpz_srcptr, mpz_srcptr, mpz_srcptr) __attribute__ ((__pure__));


 int __gmpz_congruent_2exp_p (mpz_srcptr, mpz_srcptr, mp_bitcnt_t) __attribute__ ((__pure__));


 int __gmpz_congruent_ui_p (mpz_srcptr, unsigned long, unsigned long) __attribute__ ((__pure__));


 void __gmpz_divexact (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_divexact_ui (mpz_ptr, mpz_srcptr, unsigned long);


 int __gmpz_divisible_p (mpz_srcptr, mpz_srcptr) __attribute__ ((__pure__));


 int __gmpz_divisible_ui_p (mpz_srcptr, unsigned long) __attribute__ ((__pure__));


 int __gmpz_divisible_2exp_p (mpz_srcptr, mp_bitcnt_t) __attribute__ ((__pure__));


 void __gmpz_dump (mpz_srcptr);


 void *__gmpz_export (void *, size_t *, int, size_t, int, size_t, mpz_srcptr);


 void __gmpz_fac_ui (mpz_ptr, unsigned long int);


 void __gmpz_2fac_ui (mpz_ptr, unsigned long int);


 void __gmpz_mfac_uiui (mpz_ptr, unsigned long int, unsigned long int);


 void __gmpz_primorial_ui (mpz_ptr, unsigned long int);


 void __gmpz_fdiv_q (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_fdiv_q_2exp (mpz_ptr, mpz_srcptr, mp_bitcnt_t);


 unsigned long int __gmpz_fdiv_q_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_fdiv_qr (mpz_ptr, mpz_ptr, mpz_srcptr, mpz_srcptr);


 unsigned long int __gmpz_fdiv_qr_ui (mpz_ptr, mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_fdiv_r (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_fdiv_r_2exp (mpz_ptr, mpz_srcptr, mp_bitcnt_t);


 unsigned long int __gmpz_fdiv_r_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 unsigned long int __gmpz_fdiv_ui (mpz_srcptr, unsigned long int) __attribute__ ((__pure__));


 void __gmpz_fib_ui (mpz_ptr, unsigned long int);


 void __gmpz_fib2_ui (mpz_ptr, mpz_ptr, unsigned long int);


 int __gmpz_fits_sint_p (mpz_srcptr) __attribute__ ((__pure__));


 int __gmpz_fits_slong_p (mpz_srcptr) __attribute__ ((__pure__));


 int __gmpz_fits_sshort_p (mpz_srcptr) __attribute__ ((__pure__));



 int __gmpz_fits_uint_p (mpz_srcptr) __attribute__ ((__pure__));




 int __gmpz_fits_ulong_p (mpz_srcptr) __attribute__ ((__pure__));




 int __gmpz_fits_ushort_p (mpz_srcptr) __attribute__ ((__pure__));



 void __gmpz_gcd (mpz_ptr, mpz_srcptr, mpz_srcptr);


 unsigned long int __gmpz_gcd_ui (mpz_ptr, mpz_srcptr, unsigned long int);
# 829 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 double __gmpz_get_d (mpz_srcptr) __attribute__ ((__pure__));


 double __gmpz_get_d_2exp (signed long int *, mpz_srcptr);


 long int __gmpz_get_si (mpz_srcptr) __attribute__ ((__pure__));
# 846 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 unsigned long int __gmpz_get_ui (mpz_srcptr) __attribute__ ((__pure__));




 mp_limb_t __gmpz_getlimbn (mpz_srcptr, mp_size_t) __attribute__ ((__pure__));



 mp_bitcnt_t __gmpz_hamdist (mpz_srcptr, mpz_srcptr) __attribute__ ((__pure__));


 void __gmpz_import (mpz_ptr, size_t, int, size_t, int, size_t, const void *);
# 868 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpz_init2 (mpz_ptr, mp_bitcnt_t);


 void __gmpz_inits (mpz_ptr, ...);


 void __gmpz_init_set (mpz_ptr, mpz_srcptr);


 void __gmpz_init_set_d (mpz_ptr, double);


 void __gmpz_init_set_si (mpz_ptr, signed long int);


 int __gmpz_init_set_str (mpz_ptr, const char *, int);


 void __gmpz_init_set_ui (mpz_ptr, unsigned long int);
# 899 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 int __gmpz_invert (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_ior (mpz_ptr, mpz_srcptr, mpz_srcptr);


 int __gmpz_jacobi (mpz_srcptr, mpz_srcptr) __attribute__ ((__pure__));




 int __gmpz_kronecker_si (mpz_srcptr, long) __attribute__ ((__pure__));


 int __gmpz_kronecker_ui (mpz_srcptr, unsigned long) __attribute__ ((__pure__));


 int __gmpz_si_kronecker (long, mpz_srcptr) __attribute__ ((__pure__));


 int __gmpz_ui_kronecker (unsigned long, mpz_srcptr) __attribute__ ((__pure__));


 void __gmpz_lcm (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_lcm_ui (mpz_ptr, mpz_srcptr, unsigned long);




 void __gmpz_lucnum_ui (mpz_ptr, unsigned long int);


 void __gmpz_lucnum2_ui (mpz_ptr, mpz_ptr, unsigned long int);


 int __gmpz_millerrabin (mpz_srcptr, int) __attribute__ ((__pure__));


 void __gmpz_mod (mpz_ptr, mpz_srcptr, mpz_srcptr);




 void __gmpz_mul (mpz_ptr, mpz_srcptr, mpz_srcptr);
# 954 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpz_mul_si (mpz_ptr, mpz_srcptr, long int);


 void __gmpz_mul_ui (mpz_ptr, mpz_srcptr, unsigned long int);



 void __gmpz_neg (mpz_ptr, mpz_srcptr);



 void __gmpz_nextprime (mpz_ptr, mpz_srcptr);
# 978 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 int __gmpz_perfect_power_p (mpz_srcptr) __attribute__ ((__pure__));



 int __gmpz_perfect_square_p (mpz_srcptr) __attribute__ ((__pure__));




 mp_bitcnt_t __gmpz_popcount (mpz_srcptr) __attribute__ ((__pure__));



 void __gmpz_pow_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_powm (mpz_ptr, mpz_srcptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_powm_sec (mpz_ptr, mpz_srcptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_powm_ui (mpz_ptr, mpz_srcptr, unsigned long int, mpz_srcptr);


 int __gmpz_probab_prime_p (mpz_srcptr, int) __attribute__ ((__pure__));


 void __gmpz_random (mpz_ptr, mp_size_t);


 void __gmpz_random2 (mpz_ptr, mp_size_t);


 void __gmpz_realloc2 (mpz_ptr, mp_bitcnt_t);


 mp_bitcnt_t __gmpz_remove (mpz_ptr, mpz_srcptr, mpz_srcptr);


 int __gmpz_root (mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_rootrem (mpz_ptr, mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_rrandomb (mpz_ptr, gmp_randstate_t, mp_bitcnt_t);


 mp_bitcnt_t __gmpz_scan0 (mpz_srcptr, mp_bitcnt_t) __attribute__ ((__pure__));


 mp_bitcnt_t __gmpz_scan1 (mpz_srcptr, mp_bitcnt_t) __attribute__ ((__pure__));


 void __gmpz_set (mpz_ptr, mpz_srcptr);


 void __gmpz_set_d (mpz_ptr, double);


 void __gmpz_set_f (mpz_ptr, mpf_srcptr);



 void __gmpz_set_q (mpz_ptr, mpq_srcptr);



 void __gmpz_set_si (mpz_ptr, signed long int);


 int __gmpz_set_str (mpz_ptr, const char *, int);
# 1060 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpz_setbit (mpz_ptr, mp_bitcnt_t);



 size_t __gmpz_size (mpz_srcptr) __attribute__ ((__pure__));
# 1074 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpz_sqrt (mpz_ptr, mpz_srcptr);


 void __gmpz_sqrtrem (mpz_ptr, mpz_ptr, mpz_srcptr);


 void __gmpz_sub (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_sub_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_ui_sub (mpz_ptr, unsigned long int, mpz_srcptr);


 void __gmpz_submul (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_submul_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_swap (mpz_ptr, mpz_ptr) ;


 unsigned long int __gmpz_tdiv_ui (mpz_srcptr, unsigned long int) __attribute__ ((__pure__));


 void __gmpz_tdiv_q (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_tdiv_q_2exp (mpz_ptr, mpz_srcptr, mp_bitcnt_t);


 unsigned long int __gmpz_tdiv_q_ui (mpz_ptr, mpz_srcptr, unsigned long int);
# 1117 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 unsigned long int __gmpz_tdiv_qr_ui (mpz_ptr, mpz_ptr, mpz_srcptr, unsigned long int);


 void __gmpz_tdiv_r (mpz_ptr, mpz_srcptr, mpz_srcptr);


 void __gmpz_tdiv_r_2exp (mpz_ptr, mpz_srcptr, mp_bitcnt_t);


 unsigned long int __gmpz_tdiv_r_ui (mpz_ptr, mpz_srcptr, unsigned long int);


 int __gmpz_tstbit (mpz_srcptr, mp_bitcnt_t) __attribute__ ((__pure__));


 void __gmpz_ui_pow_ui (mpz_ptr, unsigned long int, unsigned long int);


 void __gmpz_urandomb (mpz_ptr, gmp_randstate_t, mp_bitcnt_t);


 void __gmpz_urandomm (mpz_ptr, gmp_randstate_t, mpz_srcptr);



 void __gmpz_xor (mpz_ptr, mpz_srcptr, mpz_srcptr);


 mp_srcptr __gmpz_limbs_read (mpz_srcptr);


 mp_ptr __gmpz_limbs_write (mpz_ptr, mp_size_t);


 mp_ptr __gmpz_limbs_modify (mpz_ptr, mp_size_t);


 void __gmpz_limbs_finish (mpz_ptr, mp_size_t);


 mpz_srcptr __gmpz_roinit_n (mpz_ptr, mp_srcptr, mp_size_t);







 void __gmpq_abs (mpq_ptr, mpq_srcptr);



 void __gmpq_add (mpq_ptr, mpq_srcptr, mpq_srcptr);


 void __gmpq_canonicalize (mpq_ptr);


 void __gmpq_clear (mpq_ptr);


 void __gmpq_clears (mpq_ptr, ...);


 int __gmpq_cmp (mpq_srcptr, mpq_srcptr) __attribute__ ((__pure__));


 int __gmpq_cmp_si (mpq_srcptr, long, unsigned long) __attribute__ ((__pure__));


 int __gmpq_cmp_ui (mpq_srcptr, unsigned long int, unsigned long int) __attribute__ ((__pure__));


 int __gmpq_cmp_z (mpq_srcptr, mpz_srcptr) __attribute__ ((__pure__));


 void __gmpq_div (mpq_ptr, mpq_srcptr, mpq_srcptr);


 void __gmpq_div_2exp (mpq_ptr, mpq_srcptr, mp_bitcnt_t);


 int __gmpq_equal (mpq_srcptr, mpq_srcptr) __attribute__ ((__pure__));


 void __gmpq_get_num (mpz_ptr, mpq_srcptr);


 void __gmpq_get_den (mpz_ptr, mpq_srcptr);


 double __gmpq_get_d (mpq_srcptr) __attribute__ ((__pure__));


 char *__gmpq_get_str (char *, int, mpq_srcptr);


 void __gmpq_init (mpq_ptr);


 void __gmpq_inits (mpq_ptr, ...);







 void __gmpq_inv (mpq_ptr, mpq_srcptr);


 void __gmpq_mul (mpq_ptr, mpq_srcptr, mpq_srcptr);


 void __gmpq_mul_2exp (mpq_ptr, mpq_srcptr, mp_bitcnt_t);



 void __gmpq_neg (mpq_ptr, mpq_srcptr);
# 1244 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpq_set (mpq_ptr, mpq_srcptr);


 void __gmpq_set_d (mpq_ptr, double);


 void __gmpq_set_den (mpq_ptr, mpz_srcptr);


 void __gmpq_set_f (mpq_ptr, mpf_srcptr);


 void __gmpq_set_num (mpq_ptr, mpz_srcptr);


 void __gmpq_set_si (mpq_ptr, signed long int, unsigned long int);


 int __gmpq_set_str (mpq_ptr, const char *, int);


 void __gmpq_set_ui (mpq_ptr, unsigned long int, unsigned long int);


 void __gmpq_set_z (mpq_ptr, mpz_srcptr);


 void __gmpq_sub (mpq_ptr, mpq_srcptr, mpq_srcptr);


 void __gmpq_swap (mpq_ptr, mpq_ptr) ;





 void __gmpf_abs (mpf_ptr, mpf_srcptr);


 void __gmpf_add (mpf_ptr, mpf_srcptr, mpf_srcptr);


 void __gmpf_add_ui (mpf_ptr, mpf_srcptr, unsigned long int);

 void __gmpf_ceil (mpf_ptr, mpf_srcptr);


 void __gmpf_clear (mpf_ptr);


 void __gmpf_clears (mpf_ptr, ...);


 int __gmpf_cmp (mpf_srcptr, mpf_srcptr) __attribute__ ((__pure__));


 int __gmpf_cmp_z (mpf_srcptr, mpz_srcptr) __attribute__ ((__pure__));


 int __gmpf_cmp_d (mpf_srcptr, double) __attribute__ ((__pure__));


 int __gmpf_cmp_si (mpf_srcptr, signed long int) __attribute__ ((__pure__));


 int __gmpf_cmp_ui (mpf_srcptr, unsigned long int) __attribute__ ((__pure__));


 void __gmpf_div (mpf_ptr, mpf_srcptr, mpf_srcptr);


 void __gmpf_div_2exp (mpf_ptr, mpf_srcptr, mp_bitcnt_t);


 void __gmpf_div_ui (mpf_ptr, mpf_srcptr, unsigned long int);


 void __gmpf_dump (mpf_srcptr);


 int __gmpf_eq (mpf_srcptr, mpf_srcptr, mp_bitcnt_t) __attribute__ ((__pure__));


 int __gmpf_fits_sint_p (mpf_srcptr) __attribute__ ((__pure__));


 int __gmpf_fits_slong_p (mpf_srcptr) __attribute__ ((__pure__));


 int __gmpf_fits_sshort_p (mpf_srcptr) __attribute__ ((__pure__));


 int __gmpf_fits_uint_p (mpf_srcptr) __attribute__ ((__pure__));


 int __gmpf_fits_ulong_p (mpf_srcptr) __attribute__ ((__pure__));


 int __gmpf_fits_ushort_p (mpf_srcptr) __attribute__ ((__pure__));


 void __gmpf_floor (mpf_ptr, mpf_srcptr);


 double __gmpf_get_d (mpf_srcptr) __attribute__ ((__pure__));


 double __gmpf_get_d_2exp (signed long int *, mpf_srcptr);


 mp_bitcnt_t __gmpf_get_default_prec (void) __attribute__ ((__pure__));


 mp_bitcnt_t __gmpf_get_prec (mpf_srcptr) __attribute__ ((__pure__));


 long __gmpf_get_si (mpf_srcptr) __attribute__ ((__pure__));


 char *__gmpf_get_str (char *, mp_exp_t *, int, size_t, mpf_srcptr);


 unsigned long __gmpf_get_ui (mpf_srcptr) __attribute__ ((__pure__));


 void __gmpf_init (mpf_ptr);


 void __gmpf_init2 (mpf_ptr, mp_bitcnt_t);


 void __gmpf_inits (mpf_ptr, ...);


 void __gmpf_init_set (mpf_ptr, mpf_srcptr);


 void __gmpf_init_set_d (mpf_ptr, double);


 void __gmpf_init_set_si (mpf_ptr, signed long int);


 int __gmpf_init_set_str (mpf_ptr, const char *, int);


 void __gmpf_init_set_ui (mpf_ptr, unsigned long int);







 int __gmpf_integer_p (mpf_srcptr) __attribute__ ((__pure__));


 void __gmpf_mul (mpf_ptr, mpf_srcptr, mpf_srcptr);


 void __gmpf_mul_2exp (mpf_ptr, mpf_srcptr, mp_bitcnt_t);


 void __gmpf_mul_ui (mpf_ptr, mpf_srcptr, unsigned long int);


 void __gmpf_neg (mpf_ptr, mpf_srcptr);







 void __gmpf_pow_ui (mpf_ptr, mpf_srcptr, unsigned long int);


 void __gmpf_random2 (mpf_ptr, mp_size_t, mp_exp_t);


 void __gmpf_reldiff (mpf_ptr, mpf_srcptr, mpf_srcptr);


 void __gmpf_set (mpf_ptr, mpf_srcptr);


 void __gmpf_set_d (mpf_ptr, double);


 void __gmpf_set_default_prec (mp_bitcnt_t) ;


 void __gmpf_set_prec (mpf_ptr, mp_bitcnt_t);


 void __gmpf_set_prec_raw (mpf_ptr, mp_bitcnt_t) ;


 void __gmpf_set_q (mpf_ptr, mpq_srcptr);


 void __gmpf_set_si (mpf_ptr, signed long int);


 int __gmpf_set_str (mpf_ptr, const char *, int);


 void __gmpf_set_ui (mpf_ptr, unsigned long int);


 void __gmpf_set_z (mpf_ptr, mpz_srcptr);


 size_t __gmpf_size (mpf_srcptr) __attribute__ ((__pure__));


 void __gmpf_sqrt (mpf_ptr, mpf_srcptr);


 void __gmpf_sqrt_ui (mpf_ptr, unsigned long int);


 void __gmpf_sub (mpf_ptr, mpf_srcptr, mpf_srcptr);


 void __gmpf_sub_ui (mpf_ptr, mpf_srcptr, unsigned long int);


 void __gmpf_swap (mpf_ptr, mpf_ptr) ;


 void __gmpf_trunc (mpf_ptr, mpf_srcptr);


 void __gmpf_ui_div (mpf_ptr, unsigned long int, mpf_srcptr);


 void __gmpf_ui_sub (mpf_ptr, unsigned long int, mpf_srcptr);


 void __gmpf_urandomb (mpf_t, gmp_randstate_t, mp_bitcnt_t);
# 1493 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 mp_limb_t __gmpn_add (mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);




 mp_limb_t __gmpn_add_1 (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t) ;
# 1516 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 int __gmpn_cmp (mp_srcptr, mp_srcptr, mp_size_t) __attribute__ ((__pure__));




 int __gmpn_zero_p (mp_srcptr, mp_size_t) __attribute__ ((__pure__));



 void __gmpn_divexact_1 (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);





 mp_limb_t __gmpn_divexact_by3c (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);





 mp_limb_t __gmpn_divrem (mp_ptr, mp_size_t, mp_ptr, mp_size_t, mp_srcptr, mp_size_t);


 mp_limb_t __gmpn_divrem_1 (mp_ptr, mp_size_t, mp_srcptr, mp_size_t, mp_limb_t);


 mp_limb_t __gmpn_divrem_2 (mp_ptr, mp_size_t, mp_ptr, mp_size_t, mp_srcptr);


 mp_limb_t __gmpn_div_qr_1 (mp_ptr, mp_limb_t *, mp_srcptr, mp_size_t, mp_limb_t);


 mp_limb_t __gmpn_div_qr_2 (mp_ptr, mp_ptr, mp_srcptr, mp_size_t, mp_srcptr);


 mp_size_t __gmpn_gcd (mp_ptr, mp_ptr, mp_size_t, mp_ptr, mp_size_t);


 mp_limb_t __gmpn_gcd_1 (mp_srcptr, mp_size_t, mp_limb_t) __attribute__ ((__pure__));


 mp_limb_t __gmpn_gcdext_1 (mp_limb_signed_t *, mp_limb_signed_t *, mp_limb_t, mp_limb_t);
# 1569 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 size_t __gmpn_get_str (unsigned char *, int, mp_ptr, mp_size_t);


 mp_bitcnt_t __gmpn_hamdist (mp_srcptr, mp_srcptr, mp_size_t) __attribute__ ((__pure__));


 mp_limb_t __gmpn_lshift (mp_ptr, mp_srcptr, mp_size_t, unsigned int);


 mp_limb_t __gmpn_mod_1 (mp_srcptr, mp_size_t, mp_limb_t) __attribute__ ((__pure__));


 mp_limb_t __gmpn_mul (mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);


 mp_limb_t __gmpn_mul_1 (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
# 1594 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpn_sqr (mp_ptr, mp_srcptr, mp_size_t);



 mp_limb_t __gmpn_neg (mp_ptr, mp_srcptr, mp_size_t);



 void __gmpn_com (mp_ptr, mp_srcptr, mp_size_t);


 int __gmpn_perfect_square_p (mp_srcptr, mp_size_t) __attribute__ ((__pure__));


 int __gmpn_perfect_power_p (mp_srcptr, mp_size_t) __attribute__ ((__pure__));


 mp_bitcnt_t __gmpn_popcount (mp_srcptr, mp_size_t) __attribute__ ((__pure__));


 mp_size_t __gmpn_pow_1 (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t, mp_ptr);



 mp_limb_t __gmpn_preinv_mod_1 (mp_srcptr, mp_size_t, mp_limb_t, mp_limb_t) __attribute__ ((__pure__));


 void __gmpn_random (mp_ptr, mp_size_t);


 void __gmpn_random2 (mp_ptr, mp_size_t);


 mp_limb_t __gmpn_rshift (mp_ptr, mp_srcptr, mp_size_t, unsigned int);


 mp_bitcnt_t __gmpn_scan0 (mp_srcptr, mp_bitcnt_t) __attribute__ ((__pure__));


 mp_bitcnt_t __gmpn_scan1 (mp_srcptr, mp_bitcnt_t) __attribute__ ((__pure__));
# 1643 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 size_t __gmpn_sizeinbase (mp_srcptr, mp_size_t, int);


 mp_size_t __gmpn_sqrtrem (mp_ptr, mp_ptr, mp_srcptr, mp_size_t);



 mp_limb_t __gmpn_sub (mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t);




 mp_limb_t __gmpn_sub_1 (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t) ;
# 1666 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 mp_limb_t __gmpn_submul_1 (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t);
# 1675 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpn_and_n (mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);

 void __gmpn_andn_n (mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);

 void __gmpn_nand_n (mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);

 void __gmpn_ior_n (mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);

 void __gmpn_iorn_n (mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);

 void __gmpn_nior_n (mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);

 void __gmpn_xor_n (mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);

 void __gmpn_xnor_n (mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);
# 1701 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 void __gmpn_copyd (mp_ptr, mp_srcptr, mp_size_t);
# 1712 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
 mp_limb_t __gmpn_cnd_add_n (mp_limb_t, mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);

 mp_limb_t __gmpn_cnd_sub_n (mp_limb_t, mp_ptr, mp_srcptr, mp_srcptr, mp_size_t);


 mp_limb_t __gmpn_sec_add_1 (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t, mp_ptr);

 mp_size_t __gmpn_sec_add_1_itch (mp_size_t) __attribute__ ((__pure__));


 mp_limb_t __gmpn_sec_sub_1 (mp_ptr, mp_srcptr, mp_size_t, mp_limb_t, mp_ptr);

 mp_size_t __gmpn_sec_sub_1_itch (mp_size_t) __attribute__ ((__pure__));


 void __gmpn_cnd_swap (mp_limb_t, volatile mp_limb_t *, volatile mp_limb_t *, mp_size_t);


 void __gmpn_sec_mul (mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_size_t, mp_ptr);

 mp_size_t __gmpn_sec_mul_itch (mp_size_t, mp_size_t) __attribute__ ((__pure__));


 void __gmpn_sec_sqr (mp_ptr, mp_srcptr, mp_size_t, mp_ptr);

 mp_size_t __gmpn_sec_sqr_itch (mp_size_t) __attribute__ ((__pure__));


 void __gmpn_sec_powm (mp_ptr, mp_srcptr, mp_size_t, mp_srcptr, mp_bitcnt_t, mp_srcptr, mp_size_t, mp_ptr);

 mp_size_t __gmpn_sec_powm_itch (mp_size_t, mp_bitcnt_t, mp_size_t) __attribute__ ((__pure__));


 void __gmpn_sec_tabselect (volatile mp_limb_t *, volatile const mp_limb_t *, mp_size_t, mp_size_t, mp_size_t);


 mp_limb_t __gmpn_sec_div_qr (mp_ptr, mp_ptr, mp_size_t, mp_srcptr, mp_size_t, mp_ptr);

 mp_size_t __gmpn_sec_div_qr_itch (mp_size_t, mp_size_t) __attribute__ ((__pure__));

 void __gmpn_sec_div_r (mp_ptr, mp_size_t, mp_srcptr, mp_size_t, mp_ptr);

 mp_size_t __gmpn_sec_div_r_itch (mp_size_t, mp_size_t) __attribute__ ((__pure__));


 int __gmpn_sec_invert (mp_ptr, mp_ptr, mp_srcptr, mp_size_t, mp_bitcnt_t, mp_ptr);

 mp_size_t __gmpn_sec_invert_itch (mp_size_t) __attribute__ ((__pure__));
# 1779 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
extern __inline__ __attribute__ ((__gnu_inline__)) void
__gmpz_abs (mpz_ptr __gmp_w, mpz_srcptr __gmp_u)
{
  if (__gmp_w != __gmp_u)
    __gmpz_set (__gmp_w, __gmp_u);
  __gmp_w->_mp_size = ((__gmp_w->_mp_size) >= 0 ? (__gmp_w->_mp_size) : -(__gmp_w->_mp_size));
}
# 1803 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
extern __inline__ __attribute__ ((__gnu_inline__))

int
__gmpz_fits_uint_p (mpz_srcptr __gmp_z)
{
  mp_size_t __gmp_n = __gmp_z->_mp_size; mp_ptr __gmp_p = __gmp_z->_mp_d; return (__gmp_n == 0 || (__gmp_n == 1 && __gmp_p[0] <= 0xffffffffU));;
}




extern __inline__ __attribute__ ((__gnu_inline__))

int
__gmpz_fits_ulong_p (mpz_srcptr __gmp_z)
{
  mp_size_t __gmp_n = __gmp_z->_mp_size; mp_ptr __gmp_p = __gmp_z->_mp_d; return (__gmp_n == 0 || (__gmp_n == 1 && __gmp_p[0] <= 0xffffffffffffffffUL));;
}




extern __inline__ __attribute__ ((__gnu_inline__))

int
__gmpz_fits_ushort_p (mpz_srcptr __gmp_z)
{
  mp_size_t __gmp_n = __gmp_z->_mp_size; mp_ptr __gmp_p = __gmp_z->_mp_d; return (__gmp_n == 0 || (__gmp_n == 1 && __gmp_p[0] <= 0xffff));;
}




extern __inline__ __attribute__ ((__gnu_inline__))

unsigned long
__gmpz_get_ui (mpz_srcptr __gmp_z)
{
  mp_ptr __gmp_p = __gmp_z->_mp_d;
  mp_size_t __gmp_n = __gmp_z->_mp_size;
  mp_limb_t __gmp_l = __gmp_p[0];






  return (__gmp_n != 0 ? __gmp_l : 0);
# 1859 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
}




extern __inline__ __attribute__ ((__gnu_inline__))

mp_limb_t
__gmpz_getlimbn (mpz_srcptr __gmp_z, mp_size_t __gmp_n)
{
  mp_limb_t __gmp_result = 0;
  if (__builtin_expect ((__gmp_n >= 0 && __gmp_n < ((__gmp_z->_mp_size) >= 0 ? (__gmp_z->_mp_size) : -(__gmp_z->_mp_size))) != 0, 1))
    __gmp_result = __gmp_z->_mp_d[__gmp_n];
  return __gmp_result;
}



extern __inline__ __attribute__ ((__gnu_inline__)) void
__gmpz_neg (mpz_ptr __gmp_w, mpz_srcptr __gmp_u)
{
  if (__gmp_w != __gmp_u)
    __gmpz_set (__gmp_w, __gmp_u);
  __gmp_w->_mp_size = - __gmp_w->_mp_size;
}




extern __inline__ __attribute__ ((__gnu_inline__))

int
__gmpz_perfect_square_p (mpz_srcptr __gmp_a)
{
  mp_size_t __gmp_asize;
  int __gmp_result;

  __gmp_asize = __gmp_a->_mp_size;
  __gmp_result = (__gmp_asize >= 0);
  if (__builtin_expect ((__gmp_asize > 0) != 0, 1))
    __gmp_result = __gmpn_perfect_square_p (__gmp_a->_mp_d, __gmp_asize);
  return __gmp_result;
}




extern __inline__ __attribute__ ((__gnu_inline__))

mp_bitcnt_t
__gmpz_popcount (mpz_srcptr __gmp_u)
{
  mp_size_t __gmp_usize;
  mp_bitcnt_t __gmp_result;

  __gmp_usize = __gmp_u->_mp_size;
  __gmp_result = (__gmp_usize < 0 ? 0xffffffffffffffffUL : 0);
  if (__builtin_expect ((__gmp_usize > 0) != 0, 1))
    __gmp_result = __gmpn_popcount (__gmp_u->_mp_d, __gmp_usize);
  return __gmp_result;
}




extern __inline__ __attribute__ ((__gnu_inline__))

void
__gmpz_set_q (mpz_ptr __gmp_w, mpq_srcptr __gmp_u)
{
  __gmpz_tdiv_q (__gmp_w, (&((__gmp_u)->_mp_num)), (&((__gmp_u)->_mp_den)));
}




extern __inline__ __attribute__ ((__gnu_inline__))

size_t
__gmpz_size (mpz_srcptr __gmp_z)
{
  return ((__gmp_z->_mp_size) >= 0 ? (__gmp_z->_mp_size) : -(__gmp_z->_mp_size));
}






extern __inline__ __attribute__ ((__gnu_inline__)) void
__gmpq_abs (mpq_ptr __gmp_w, mpq_srcptr __gmp_u)
{
  if (__gmp_w != __gmp_u)
    __gmpq_set (__gmp_w, __gmp_u);
  __gmp_w->_mp_num._mp_size = ((__gmp_w->_mp_num._mp_size) >= 0 ? (__gmp_w->_mp_num._mp_size) : -(__gmp_w->_mp_num._mp_size));
}



extern __inline__ __attribute__ ((__gnu_inline__)) void
__gmpq_neg (mpq_ptr __gmp_w, mpq_srcptr __gmp_u)
{
  if (__gmp_w != __gmp_u)
    __gmpq_set (__gmp_w, __gmp_u);
  __gmp_w->_mp_num._mp_size = - __gmp_w->_mp_num._mp_size;
}
# 2201 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
extern __inline__ __attribute__ ((__gnu_inline__))

mp_limb_t
__gmpn_add (mp_ptr __gmp_wp, mp_srcptr __gmp_xp, mp_size_t __gmp_xsize, mp_srcptr __gmp_yp, mp_size_t __gmp_ysize)
{
  mp_limb_t __gmp_c;
  do { mp_size_t __gmp_i; mp_limb_t __gmp_x; __gmp_i = (__gmp_ysize); if (__gmp_i != 0) { if (__gmpn_add_n (__gmp_wp, __gmp_xp, __gmp_yp, __gmp_i)) { do { if (__gmp_i >= (__gmp_xsize)) { (__gmp_c) = 1; goto __gmp_done; } __gmp_x = (__gmp_xp)[__gmp_i]; } while ((((__gmp_wp)[__gmp_i++] = (__gmp_x + 1) & ((~ ((mp_limb_t) (0))) >> 0)) == 0)); } } if ((__gmp_wp) != (__gmp_xp)) do { mp_size_t __gmp_j; ; for (__gmp_j = (__gmp_i); __gmp_j < (__gmp_xsize); __gmp_j++) (__gmp_wp)[__gmp_j] = (__gmp_xp)[__gmp_j]; } while (0); (__gmp_c) = 0; __gmp_done: ; } while (0);
  return __gmp_c;
}




extern __inline__ __attribute__ ((__gnu_inline__))

mp_limb_t
__gmpn_add_1 (mp_ptr __gmp_dst, mp_srcptr __gmp_src, mp_size_t __gmp_size, mp_limb_t __gmp_n)
{
  mp_limb_t __gmp_c;
  do { mp_size_t __gmp_i; mp_limb_t __gmp_x, __gmp_r; __gmp_x = (__gmp_src)[0]; __gmp_r = __gmp_x + (__gmp_n); (__gmp_dst)[0] = __gmp_r; if (((__gmp_r) < ((__gmp_n)))) { (__gmp_c) = 1; for (__gmp_i = 1; __gmp_i < (__gmp_size);) { __gmp_x = (__gmp_src)[__gmp_i]; __gmp_r = __gmp_x + 1; (__gmp_dst)[__gmp_i] = __gmp_r; ++__gmp_i; if (!((__gmp_r) < (1))) { if ((__gmp_src) != (__gmp_dst)) do { mp_size_t __gmp_j; ; for (__gmp_j = (__gmp_i); __gmp_j < (__gmp_size); __gmp_j++) (__gmp_dst)[__gmp_j] = (__gmp_src)[__gmp_j]; } while (0); (__gmp_c) = 0; break; } } } else { if ((__gmp_src) != (__gmp_dst)) do { mp_size_t __gmp_j; ; for (__gmp_j = (1); __gmp_j < (__gmp_size); __gmp_j++) (__gmp_dst)[__gmp_j] = (__gmp_src)[__gmp_j]; } while (0); (__gmp_c) = 0; } } while (0);
  return __gmp_c;
}




extern __inline__ __attribute__ ((__gnu_inline__))

int
__gmpn_cmp (mp_srcptr __gmp_xp, mp_srcptr __gmp_yp, mp_size_t __gmp_size)
{
  int __gmp_result;
  do { mp_size_t __gmp_i; mp_limb_t __gmp_x, __gmp_y; (__gmp_result) = 0; __gmp_i = (__gmp_size); while (--__gmp_i >= 0) { __gmp_x = (__gmp_xp)[__gmp_i]; __gmp_y = (__gmp_yp)[__gmp_i]; if (__gmp_x != __gmp_y) { (__gmp_result) = (__gmp_x > __gmp_y ? 1 : -1); break; } } } while (0);
  return __gmp_result;
}




extern __inline__ __attribute__ ((__gnu_inline__))

int
__gmpn_zero_p (mp_srcptr __gmp_p, mp_size_t __gmp_n)
{

    do {
      if (__gmp_p[--__gmp_n] != 0)
 return 0;
    } while (__gmp_n != 0);
  return 1;
}




extern __inline__ __attribute__ ((__gnu_inline__))

mp_limb_t
__gmpn_sub (mp_ptr __gmp_wp, mp_srcptr __gmp_xp, mp_size_t __gmp_xsize, mp_srcptr __gmp_yp, mp_size_t __gmp_ysize)
{
  mp_limb_t __gmp_c;
  do { mp_size_t __gmp_i; mp_limb_t __gmp_x; __gmp_i = (__gmp_ysize); if (__gmp_i != 0) { if (__gmpn_sub_n (__gmp_wp, __gmp_xp, __gmp_yp, __gmp_i)) { do { if (__gmp_i >= (__gmp_xsize)) { (__gmp_c) = 1; goto __gmp_done; } __gmp_x = (__gmp_xp)[__gmp_i]; } while ((((__gmp_wp)[__gmp_i++] = (__gmp_x - 1) & ((~ ((mp_limb_t) (0))) >> 0)), __gmp_x == 0)); } } if ((__gmp_wp) != (__gmp_xp)) do { mp_size_t __gmp_j; ; for (__gmp_j = (__gmp_i); __gmp_j < (__gmp_xsize); __gmp_j++) (__gmp_wp)[__gmp_j] = (__gmp_xp)[__gmp_j]; } while (0); (__gmp_c) = 0; __gmp_done: ; } while (0);
  return __gmp_c;
}




extern __inline__ __attribute__ ((__gnu_inline__))

mp_limb_t
__gmpn_sub_1 (mp_ptr __gmp_dst, mp_srcptr __gmp_src, mp_size_t __gmp_size, mp_limb_t __gmp_n)
{
  mp_limb_t __gmp_c;
  do { mp_size_t __gmp_i; mp_limb_t __gmp_x, __gmp_r; __gmp_x = (__gmp_src)[0]; __gmp_r = __gmp_x - (__gmp_n); (__gmp_dst)[0] = __gmp_r; if (((__gmp_x) < ((__gmp_n)))) { (__gmp_c) = 1; for (__gmp_i = 1; __gmp_i < (__gmp_size);) { __gmp_x = (__gmp_src)[__gmp_i]; __gmp_r = __gmp_x - 1; (__gmp_dst)[__gmp_i] = __gmp_r; ++__gmp_i; if (!((__gmp_x) < (1))) { if ((__gmp_src) != (__gmp_dst)) do { mp_size_t __gmp_j; ; for (__gmp_j = (__gmp_i); __gmp_j < (__gmp_size); __gmp_j++) (__gmp_dst)[__gmp_j] = (__gmp_src)[__gmp_j]; } while (0); (__gmp_c) = 0; break; } } } else { if ((__gmp_src) != (__gmp_dst)) do { mp_size_t __gmp_j; ; for (__gmp_j = (1); __gmp_j < (__gmp_size); __gmp_j++) (__gmp_dst)[__gmp_j] = (__gmp_src)[__gmp_j]; } while (0); (__gmp_c) = 0; } } while (0);
  return __gmp_c;
}




extern __inline__ __attribute__ ((__gnu_inline__))

mp_limb_t
__gmpn_neg (mp_ptr __gmp_rp, mp_srcptr __gmp_up, mp_size_t __gmp_n)
{
  while (*__gmp_up == 0)
    {
      *__gmp_rp = 0;
      if (!--__gmp_n)
 return 0;
      ++__gmp_up; ++__gmp_rp;
    }

  *__gmp_rp = (- *__gmp_up) & ((~ ((mp_limb_t) (0))) >> 0);

  if (--__gmp_n)
    __gmpn_com (++__gmp_rp, ++__gmp_up, __gmp_n);

  return 1;
}
# 2370 "/home/kladko/sgxwallet/tgmp-build/include/sgx_tgmp.h"
enum
{
  GMP_ERROR_NONE = 0,
  GMP_ERROR_UNSUPPORTED_ARGUMENT = 1,
  GMP_ERROR_DIVISION_BY_ZERO = 2,
  GMP_ERROR_SQRT_OF_NEGATIVE = 4,
  GMP_ERROR_INVALID_ARGUMENT = 8
};
# 10 "secure_enclave_t.h" 2
# 19 "secure_enclave_t.h"
void tgmp_init(void);
void trustedEMpzAdd(mpz_t* c, mpz_t* a, mpz_t* b);
void trustedEMpzMul(mpz_t* c, mpz_t* a, mpz_t* b);
void trustedEMpzDiv(mpz_t* c, mpz_t* a, mpz_t* b);
void trustedEMpfDiv(mpf_t* c, mpf_t* a, mpf_t* b);
void trustedGenerateEcdsaKey(int* err_status, char* err_string, uint8_t* encrypted_key, uint32_t* enc_len, char* pub_key_x, char* pub_key_y);
void trustedEncryptKey(int* err_status, char* err_string, char* key, uint8_t* encrypted_key, uint32_t* enc_len);
void trustedDecryptKey(int* err_status, char* err_string, uint8_t* encrypted_key, uint32_t enc_len, char* key);
void trustedBlsSignMessage(int* err_status, char* err_string, uint8_t* encrypted_key, uint32_t enc_len, char* hashX, char* hashY, char* signature);
void trustedGenDkgSecret(int* err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint32_t* enc_len, size_t _t);
void trustedDecryptDkgSecret(int* err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint8_t* decrypted_dkg_secret, uint32_t enc_len);
void trustedGetSecretShares(int* err_status, char* err_string, uint8_t* decrypted_dkg_secret, uint32_t enc_len, char* secret_shares, unsigned int _t, unsigned int _n);
void trustedGetPublicShares(int* err_status, char* err_string, uint8_t* decrypted_dkg_secret, uint32_t enc_len, char* public_shares, unsigned int _t, unsigned int _n);
void trustedEcdsaSign(int* err_status, char* err_string, uint8_t* encrypted_key, uint32_t dec_len, unsigned char* hash, char* signature, int test_len);

sgx_status_t oc_realloc(uint64_t* retval, void* optr, size_t osz, size_t nsz);
sgx_status_t oc_free(void* optr, size_t sz);
sgx_status_t u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
# 43 "secure_enclave.c" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h" 1
# 43 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx.h" 1
# 36 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_attributes.h" 1
# 53 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_attributes.h"
typedef struct _attributes_t
{
    uint64_t flags;
    uint64_t xfrm;
} sgx_attributes_t;


typedef uint32_t sgx_misc_select_t;

typedef struct _sgx_misc_attribute_t {
    sgx_attributes_t secs_attr;
    sgx_misc_select_t misc_select;
} sgx_misc_attribute_t;
# 37 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx.h" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_key.h" 1
# 64 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_key.h"
typedef uint8_t sgx_key_128bit_t[16];
typedef uint16_t sgx_isv_svn_t;
typedef uint16_t sgx_config_svn_t;
typedef uint8_t sgx_config_id_t[64];


typedef struct _sgx_cpu_svn_t
{
    uint8_t svn[16];
} sgx_cpu_svn_t;

typedef struct _sgx_key_id_t
{
    uint8_t id[32];
} sgx_key_id_t;



typedef struct _key_request_t
{
    uint16_t key_name;
    uint16_t key_policy;
    sgx_isv_svn_t isv_svn;
    uint16_t reserved1;
    sgx_cpu_svn_t cpu_svn;
    sgx_attributes_t attribute_mask;
    sgx_key_id_t key_id;
    sgx_misc_select_t misc_mask;
    sgx_config_svn_t config_svn;
    uint8_t reserved2[434];
} sgx_key_request_t;
# 38 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx.h" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_report.h" 1
# 52 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_report.h"
typedef struct _sgx_measurement_t
{
    uint8_t m[32];
} sgx_measurement_t;

typedef uint8_t sgx_mac_t[16];

typedef struct _sgx_report_data_t
{
    uint8_t d[64];
} sgx_report_data_t;

typedef uint16_t sgx_prod_id_t;

typedef uint8_t sgx_isvext_prod_id_t[16];
typedef uint8_t sgx_isvfamily_id_t[16];






typedef struct _target_info_t
{
    sgx_measurement_t mr_enclave;
    sgx_attributes_t attributes;
    uint8_t reserved1[2];
    sgx_config_svn_t config_svn;
    sgx_misc_select_t misc_select;
    uint8_t reserved2[8];
    sgx_config_id_t config_id;
    uint8_t reserved3[384];
} sgx_target_info_t;

typedef struct _report_body_t
{
    sgx_cpu_svn_t cpu_svn;
    sgx_misc_select_t misc_select;
    uint8_t reserved1[12];
    sgx_isvext_prod_id_t isv_ext_prod_id;
    sgx_attributes_t attributes;
    sgx_measurement_t mr_enclave;
    uint8_t reserved2[32];
    sgx_measurement_t mr_signer;
    uint8_t reserved3[32];
    sgx_config_id_t config_id;
    sgx_prod_id_t isv_prod_id;
    sgx_isv_svn_t isv_svn;
    sgx_config_svn_t config_svn;
    uint8_t reserved4[42];
    sgx_isvfamily_id_t isv_family_id;
    sgx_report_data_t report_data;
} sgx_report_body_t;

typedef struct _report_t
{
    sgx_report_body_t body;
    sgx_key_id_t key_id;
    sgx_mac_t mac;
} sgx_report_t;
# 39 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx.h" 2
# 44 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h" 2
# 63 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
typedef struct _sgx_ec256_dh_shared_t
{
    uint8_t s[32];
} sgx_ec256_dh_shared_t;

typedef struct _sgx_ec256_private_t
{
    uint8_t r[32];
} sgx_ec256_private_t;

typedef struct _sgx_ec256_public_t
{
    uint8_t gx[32];
    uint8_t gy[32];
} sgx_ec256_public_t;

typedef struct _sgx_ec256_signature_t
{
    uint32_t x[(32/sizeof(uint32_t))];
    uint32_t y[(32/sizeof(uint32_t))];
} sgx_ec256_signature_t;

typedef struct _sgx_rsa3072_public_key_t
{
    uint8_t mod[384];
    uint8_t exp[4];
} sgx_rsa3072_public_key_t;

typedef struct _sgx_rsa3072_key_t
{
    uint8_t mod[384];
    uint8_t d[384];
    uint8_t e[4];
} sgx_rsa3072_key_t;

typedef uint8_t sgx_rsa3072_signature_t[384];

typedef void* sgx_sha_state_handle_t;
typedef void* sgx_hmac_state_handle_t;
typedef void* sgx_cmac_state_handle_t;
typedef void* sgx_ecc_state_handle_t;
typedef void* sgx_aes_state_handle_t;

typedef uint8_t sgx_sha1_hash_t[20];
typedef uint8_t sgx_sha256_hash_t[32];

typedef uint8_t sgx_aes_gcm_128bit_key_t[16];
typedef uint8_t sgx_aes_gcm_128bit_tag_t[16];
typedef uint8_t sgx_hmac_256bit_key_t[32];
typedef uint8_t sgx_hmac_256bit_tag_t[32];
typedef uint8_t sgx_cmac_128bit_key_t[16];
typedef uint8_t sgx_cmac_128bit_tag_t[16];
typedef uint8_t sgx_aes_ctr_128bit_key_t[16];

typedef enum {
    SGX_EC_VALID,

    SGX_EC_COMPOSITE_BASE,
    SGX_EC_COMPLICATED_BASE,
    SGX_EC_IS_ZERO_DISCRIMINANT,
    SGX_EC_COMPOSITE_ORDER,
    SGX_EC_INVALID_ORDER,
    SGX_EC_IS_WEAK_MOV,
    SGX_EC_IS_WEAK_SSA,
    SGX_EC_IS_SUPER_SINGULAR,

    SGX_EC_INVALID_PRIVATE_KEY,
    SGX_EC_INVALID_PUBLIC_KEY,
    SGX_EC_INVALID_KEY_PAIR,

    SGX_EC_POINT_OUT_OF_GROUP,
    SGX_EC_POINT_IS_AT_INFINITY,
    SGX_EC_POINT_IS_NOT_VALID,

    SGX_EC_POINT_IS_EQUAL,
    SGX_EC_POINT_IS_NOT_EQUAL,

    SGX_EC_INVALID_SIGNATURE
} sgx_generic_ecresult_t;


typedef enum {
 SGX_RSA_VALID,

 SGX_RSA_INVALID_SIGNATURE
} sgx_rsa_result_t;

typedef enum {
    SGX_RSA_PRIVATE_KEY,

    SGX_RSA_PUBLIC_KEY
} sgx_rsa_key_type_t;
# 174 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
typedef struct _rsa_params_t {
 unsigned int n[(384/sizeof(unsigned int))];
 unsigned int e[(4/sizeof(unsigned int))];
 unsigned int d[(384/sizeof(unsigned int))];
 unsigned int p[(192/sizeof(unsigned int))];
 unsigned int q[(192/sizeof(unsigned int))];
 unsigned int dmp1[(192/sizeof(unsigned int))];
 unsigned int dmq1[(192/sizeof(unsigned int))];
 unsigned int iqmp[(192/sizeof(unsigned int))];
}rsa_params_t;
# 220 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_sha256_msg(const uint8_t *p_src, uint32_t src_len, sgx_sha256_hash_t *p_hash);
    sgx_status_t sgx_sha1_msg(const uint8_t *p_src, uint32_t src_len, sgx_sha1_hash_t *p_hash);







    sgx_status_t sgx_sha256_init(sgx_sha_state_handle_t* p_sha_handle);
    sgx_status_t sgx_sha1_init(sgx_sha_state_handle_t* p_sha_handle);
# 240 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_sha256_update(const uint8_t *p_src, uint32_t src_len, sgx_sha_state_handle_t sha_handle);
    sgx_status_t sgx_sha1_update(const uint8_t *p_src, size_t src_len, sgx_sha_state_handle_t sha_handle);
# 250 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_sha256_get_hash(sgx_sha_state_handle_t sha_handle, sgx_sha256_hash_t *p_hash);
    sgx_status_t sgx_sha1_get_hash(sgx_sha_state_handle_t sha_handle, sgx_sha1_hash_t *p_hash);







    sgx_status_t sgx_sha256_close(sgx_sha_state_handle_t sha_handle);
    sgx_status_t sgx_sha1_close(sgx_sha_state_handle_t sha_handle);
# 307 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *p_key,
                                                const uint8_t *p_src,
                                                uint32_t src_len,
                                                uint8_t *p_dst,
                                                const uint8_t *p_iv,
                                                uint32_t iv_len,
                                                const uint8_t *p_aad,
                                                uint32_t aad_len,
                                                sgx_aes_gcm_128bit_tag_t *p_out_mac);
    sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *p_key,
                                                const uint8_t *p_src,
                                                uint32_t src_len,
                                                uint8_t *p_dst,
                                                const uint8_t *p_iv,
                                                uint32_t iv_len,
                                                const uint8_t *p_aad,
                                                uint32_t aad_len,
                                                const sgx_aes_gcm_128bit_tag_t *p_in_mac);
# 361 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *p_key,
                                                    const uint8_t *p_src,
                                                    uint32_t src_len,
                                                    sgx_cmac_128bit_tag_t *p_mac);







    sgx_status_t sgx_cmac128_init(const sgx_cmac_128bit_key_t *p_key, sgx_cmac_state_handle_t* p_cmac_handle);
# 382 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_cmac128_update(const uint8_t *p_src, uint32_t src_len, sgx_cmac_state_handle_t cmac_handle);
# 391 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_cmac128_final(sgx_cmac_state_handle_t cmac_handle, sgx_cmac_128bit_tag_t *p_hash);







    sgx_status_t sgx_cmac128_close(sgx_cmac_state_handle_t cmac_handle);
# 412 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_hmac_sha256_msg(const unsigned char *p_src, int src_len, const unsigned char *p_key, int key_len,
        unsigned char *p_mac, int mac_len);
# 422 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_hmac256_init(const unsigned char *p_key, int key_len, sgx_hmac_state_handle_t *p_hmac_handle);
# 431 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_hmac256_update(const uint8_t *p_src, int src_len, sgx_hmac_state_handle_t hmac_handle);
# 440 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_hmac256_final(unsigned char *p_hash, int hash_len, sgx_hmac_state_handle_t hmac_handle);






    sgx_status_t sgx_hmac256_close(sgx_hmac_state_handle_t hmac_handle);
# 491 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_aes_ctr_encrypt(
                        const sgx_aes_ctr_128bit_key_t *p_key,
                        const uint8_t *p_src,
                        const uint32_t src_len,
                        uint8_t *p_ctr,
                        const uint32_t ctr_inc_bits,
                        uint8_t *p_dst);

    sgx_status_t sgx_aes_ctr_decrypt(
                        const sgx_aes_ctr_128bit_key_t *p_key,
                        const uint8_t *p_src,
                        const uint32_t src_len,
                        uint8_t *p_ctr,
                        const uint32_t ctr_inc_bits,
                        uint8_t *p_dst);
# 540 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t* p_ecc_handle);







    sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t ecc_handle);
# 574 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_ecc256_create_key_pair(sgx_ec256_private_t *p_private,
                                                sgx_ec256_public_t *p_public,
                                                sgx_ecc_state_handle_t ecc_handle);
# 586 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_ecc256_check_point(const sgx_ec256_public_t *p_point,
                                    const sgx_ecc_state_handle_t ecc_handle,
                                    int *p_valid);
# 639 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_ecc256_compute_shared_dhkey(sgx_ec256_private_t *p_private_b,
                                                    sgx_ec256_public_t *p_public_ga,
                                                    sgx_ec256_dh_shared_t *p_shared_key,
                                                    sgx_ecc_state_handle_t ecc_handle);
# 674 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_ecdsa_sign(const uint8_t *p_data,
                                    uint32_t data_size,
                                    sgx_ec256_private_t *p_private,
                                    sgx_ec256_signature_t *p_signature,
                                    sgx_ecc_state_handle_t ecc_handle);
# 707 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_ecdsa_verify(const uint8_t *p_data,
                                        uint32_t data_size,
                                        const sgx_ec256_public_t *p_public,
                                        sgx_ec256_signature_t *p_signature,
                                        uint8_t *p_result,
                                        sgx_ecc_state_handle_t ecc_handle);
# 738 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_ecdsa_verify_hash(const uint8_t *p_data,
                                        const sgx_ec256_public_t *p_public,
                                        sgx_ec256_signature_t *p_signature,
                                        uint8_t *p_result,
                                        sgx_ecc_state_handle_t ecc_handle);
# 759 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_rsa3072_sign(const uint8_t *p_data,
        uint32_t data_size,
        const sgx_rsa3072_key_t *p_key,
        sgx_rsa3072_signature_t *p_signature);
# 783 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_rsa3072_verify(const uint8_t *p_data,
        uint32_t data_size,
        const sgx_rsa3072_public_key_t *p_public,
        const sgx_rsa3072_signature_t *p_signature,
  sgx_rsa_result_t *p_result);
# 798 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_create_rsa_key_pair(int n_byte_size, int e_byte_size, unsigned char *p_n, unsigned char *p_d, unsigned char *p_e,
        unsigned char *p_p, unsigned char *p_q, unsigned char *p_dmp1,
        unsigned char *p_dmq1, unsigned char *p_iqmp);
# 813 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_rsa_priv_decrypt_sha256(void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len);
# 826 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_rsa_pub_encrypt_sha256(void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len);
# 843 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_create_rsa_priv2_key(int mod_size, int exp_size, const unsigned char *p_rsa_key_e, const unsigned char *p_rsa_key_p, const unsigned char *p_rsa_key_q,
        const unsigned char *p_rsa_key_dmp1, const unsigned char *p_rsa_key_dmq1, const unsigned char *p_rsa_key_iqmp,
        void **new_pri_key2);
# 858 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_create_rsa_pub1_key(int mod_size, int exp_size, const unsigned char *le_n, const unsigned char *le_e, void **new_pub_key1);
# 873 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_free_rsa_key(void *p_rsa_key, sgx_rsa_key_type_t key_type, int mod_size, int exp_size);
# 887 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_calculate_ecdsa_priv_key(const unsigned char* hash_drg, int hash_drg_len,
        const unsigned char* sgx_nistp256_r_m1, int sgx_nistp256_r_m1_len,
        unsigned char* out_key, int out_key_len);
# 899 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_ecc256_calculate_pub_from_priv(const sgx_ec256_private_t *p_att_priv_key,
        sgx_ec256_public_t *p_att_pub_key);
# 914 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_aes_gcm128_enc_init(
        const uint8_t *p_key,
        const uint8_t *p_iv,
        uint32_t iv_len,
        const uint8_t *p_aad,
        uint32_t aad_len,
        sgx_aes_state_handle_t *aes_gcm_state);
# 930 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_aes_gcm128_enc_get_mac(uint8_t *mac, sgx_aes_state_handle_t aes_gcm_state);
# 939 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_aes_gcm_close(sgx_aes_state_handle_t aes_gcm_state);
# 951 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h"
    sgx_status_t sgx_aes_gcm128_enc_update(
        uint8_t *p_src,
        uint32_t src_len,
        uint8_t *p_dst,
        sgx_aes_state_handle_t aes_gcm_state);
# 44 "secure_enclave.c" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h" 1
# 43 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tcrypto.h" 1
# 44 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h" 2




typedef struct _aes_gcm_data_t
{
    uint32_t payload_size;
    uint8_t reserved[12];
    uint8_t payload_tag[16];
    uint8_t payload[];
} sgx_aes_gcm_data_t;

typedef struct _sealed_data_t
{
    sgx_key_request_t key_request;
    uint32_t plain_text_offset;
    uint8_t reserved[12];
    sgx_aes_gcm_data_t aes_data;
} sgx_sealed_data_t;
# 78 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    uint32_t sgx_calc_sealed_data_size(const uint32_t add_mac_txt_size, const uint32_t txt_encrypt_size);
# 90 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    uint32_t sgx_get_add_mac_txt_len(const sgx_sealed_data_t* p_sealed_data);
# 102 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    uint32_t sgx_get_encrypt_txt_len(const sgx_sealed_data_t* p_sealed_data);
# 130 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    sgx_status_t sgx_seal_data(const uint32_t additional_MACtext_length,
        const uint8_t *p_additional_MACtext,
        const uint32_t text2encrypt_length,
        const uint8_t *p_text2encrypt,
        const uint32_t sealed_data_size,
        sgx_sealed_data_t *p_sealed_data);
# 159 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    sgx_status_t sgx_seal_data_ex(const uint16_t key_policy,
        const sgx_attributes_t attribute_mask,
        const sgx_misc_select_t misc_mask,
        const uint32_t additional_MACtext_length,
        const uint8_t *p_additional_MACtext,
        const uint32_t text2encrypt_length,
        const uint8_t *p_text2encrypt,
        const uint32_t sealed_data_size,
        sgx_sealed_data_t *p_sealed_data);
# 186 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    sgx_status_t sgx_unseal_data(const sgx_sealed_data_t *p_sealed_data,
        uint8_t *p_additional_MACtext,
        uint32_t *p_additional_MACtext_length,
        uint8_t *p_decrypted_text,
        uint32_t *p_decrypted_text_length);
# 210 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    sgx_status_t sgx_mac_aadata(const uint32_t additional_MACtext_length,
        const uint8_t *p_additional_MACtext,
        const uint32_t sealed_data_size,
        sgx_sealed_data_t *p_sealed_data);
# 231 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    sgx_status_t sgx_mac_aadata_ex(const uint16_t key_policy,
        const sgx_attributes_t attribute_mask,
        const sgx_misc_select_t misc_mask,
        const uint32_t additional_MACtext_length,
        const uint8_t *p_additional_MACtext,
        const uint32_t sealed_data_size,
        sgx_sealed_data_t *p_sealed_data);
# 251 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_tseal.h"
    sgx_status_t sgx_unmac_aadata(const sgx_sealed_data_t *p_sealed_data,
        uint8_t *p_additional_MACtext,
        uint32_t *p_additional_MACtext_length);
# 45 "secure_enclave.c" 2

# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_trts.h" 1
# 52 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_trts.h"
int sgx_is_within_enclave(const void *addr, size_t size);
# 63 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_trts.h"
int sgx_is_outside_enclave(const void *addr, size_t size);







int sgx_is_enclave_crashed(void) __attribute__((section(".nipx")));
# 83 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/sgx_trts.h"
sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes);
# 47 "secure_enclave.c" 2

# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/math.h" 1
# 24 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/math.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/float.h" 1
# 25 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/math.h" 2

typedef __float_t float_t;
typedef __double_t double_t;
# 82 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/math.h"


extern char __infinity[];




extern char __nan[];





double acos(double);
double asin(double);
double atan(double);
double atan2(double, double);
double cos(double);
double sin(double);
double tan(double);

double cosh(double);
double sinh(double);
double tanh(double);

double exp(double);
double frexp(double, int *);
double ldexp(double, int);
double log(double);
double log10(double);
double modf(double, double *);

double pow(double, double);
double sqrt(double);

double ceil(double);
double fabs(double);
double floor(double);
double fmod(double, double);




double acosh(double);
double asinh(double);
double atanh(double);

double exp2(double);
double expm1(double);
int ilogb(double);
double log1p(double);
double log2(double);
double logb(double);
double scalbn(double, int);
double scalbln(double, long int);

double cbrt(double);
double hypot(double, double);

double erf(double);
double erfc(double);
double lgamma(double);
double tgamma(double);

double nearbyint(double);
double rint(double);
long int lrint(double);
long long int llrint(double);
double round(double);
long int lround(double);
long long int llround(double);
double trunc(double);

double remainder(double, double);
double remquo(double, double, int *);

double copysign(double, double);
double nan(const char *);
double nextafter(double, double);

double fdim(double, double);
double fmax(double, double);
double fmin(double, double);

double fma(double, double, double);





float acosf(float);
float asinf(float);
float atanf(float);
float atan2f(float, float);
float cosf(float);
float sinf(float);
float tanf(float);

float acoshf(float);
float asinhf(float);
float atanhf(float);
float coshf(float);
float sinhf(float);
float tanhf(float);

float expf(float);
float exp2f(float);
float expm1f(float);
float frexpf(float, int *);
int ilogbf(float);
float ldexpf(float, int);
float logf(float);
float log10f(float);
float log1pf(float);
float log2f(float);
float logbf(float);
float modff(float, float *);
float scalbnf(float, int);
float scalblnf(float, long int);

float cbrtf(float);
float fabsf(float);
float hypotf(float, float);
float powf(float, float);
float sqrtf(float);

float erff(float);
float erfcf(float);
float lgammaf(float);
float tgammaf(float);

float ceilf(float);
float floorf(float);
float nearbyintf(float);

float rintf(float);
long int lrintf(float);
long long int llrintf(float);
float roundf(float);
long int lroundf(float);
long long int llroundf(float);
float truncf(float);

float fmodf(float, float);
float remainderf(float, float);
float remquof(float, float, int *);

float copysignf(float, float);
float nanf(const char *);
float nextafterf(float, float);

float fdimf(float, float);
float fmaxf(float, float);
float fminf(float, float);

float fmaf(float, float, float);
# 247 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/math.h"
long double acosl(long double);
long double asinl(long double);
long double atanl(long double);
long double atan2l(long double, long double);
long double cosl(long double);
long double sinl(long double);
long double tanl(long double);

long double acoshl(long double);
long double asinhl(long double);
long double atanhl(long double);
long double coshl(long double);
long double sinhl(long double);
long double tanhl(long double);

long double expl(long double);
long double exp2l(long double);
long double expm1l(long double);
long double frexpl(long double, int *);
int ilogbl(long double);
long double ldexpl(long double, int);
long double logl(long double);
long double log10l(long double);
long double log1pl(long double);
long double log2l(long double);
long double logbl(long double);
long double modfl(long double, long double *);
long double scalbnl(long double, int);
long double scalblnl(long double, long int);

long double cbrtl(long double);
long double fabsl(long double);
long double hypotl(long double, long double);
long double powl(long double, long double);
long double sqrtl(long double);

long double erfl(long double);
long double erfcl(long double);
long double lgammal(long double);
long double tgammal(long double);

long double ceill(long double);
long double floorl(long double);
long double nearbyintl(long double);
long double rintl(long double);
long int lrintl(long double);
long long int llrintl(long double);
long double roundl(long double);
long int lroundl(long double);
long long int llroundl(long double);
long double truncl(long double);

long double fmodl(long double, long double);
long double remainderl(long double, long double);
long double remquol(long double, long double, int *);

long double copysignl(long double, long double);
long double nanl(const char *);
long double nextafterl(long double, long double);

long double fdiml(long double, long double);
long double fmaxl(long double, long double);
long double fminl(long double, long double);
long double fmal(long double, long double, long double);
# 319 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/math.h"
double nexttoward(double, long double);
float nexttowardf(float, long double);

long double nexttowardl(long double, long double);




int __fpclassify(double);
int __fpclassifyf(float);
int __isfinite(double);
int __isfinitef(float);
int __isinf(double);
int __isinff(float);
int __isnan(double);
int __isnanf(float);
int __isnormal(double);
int __isnormalf(float);
int __signbit(double);
int __signbitf(float);

int __fpclassifyl(long double);
int __isfinitel(long double);
int __isinfl(long double);
int __isnanl(long double);
int __isnormall(long double);
int __signbitl(long double);




double drem(double, double);
double exp10(double);
double gamma(double);
double gamma_r(double, int *);
double j0(double);
double j1(double);
double jn(int, double);
double lgamma_r(double, int *);
double pow10(double);
double scalb(double, double);

double significand(double);
void sincos(double, double *, double *);
double y0(double);
double y1(double);
double yn(int, double);


int finite(double);

float dremf(float, float);
float exp10f(float);
float gammaf(float);
float gammaf_r(float, int *);
float j0f(float);
float j1f(float);
float jnf(int, float);
float lgammaf_r(float, int *);
float pow10f(float);
float scalbf(float, float);
int signbitf(float);
float significandf(float);
void sincosf(float, float *, float *);
float y0f(float);
float y1f(float);
float ynf(int, float);
int finitef(float);
int isinff(float);
int isnanf(float);

long double dreml(long double, long double);
long double exp10l(long double);
long double gammal(long double);
long double gammal_r(long double, int *);
long double j0l(long double);
long double j1l(long double);
long double jnl(int, long double);
long double lgammal_r(long double, int *);
long double pow10l(long double);
long double scalbl(long double, long double);
int signbitl(long double);
long double significandl(long double);
void sincosl(long double, long double *, long double *);
long double y1l(long double);
long double y0l(long double);
long double ynl(int, long double);
int finitel(long double);
int isinfl(long double);
int isnanl(long double);
# 428 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/math.h"

# 49 "secure_enclave.c" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/string.h" 1
# 48 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/string.h"
typedef int errno_t;
# 59 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/string.h"


void * memchr(const void *, int, size_t);
int memcmp(const void *, const void *, size_t);
void * memcpy(void *, const void *, size_t);
void * memmove(void *, const void *, size_t);
void * memset(void *, int, size_t);
char * strchr(const char *, int);
int strcmp(const char *, const char *);
int strcoll(const char *, const char *);
size_t strcspn(const char *, const char *);
char * strerror(int);
size_t strlen(const char *);
char * strncat(char *, const char *, size_t);
int strncmp(const char *, const char *, size_t);
char * strncpy(char *, const char *, size_t);
char * strpbrk(const char *, const char *);
char * strrchr(const char *, int);
size_t strspn(const char *, const char *);
char * strstr(const char *, const char *);
char * strtok(char *, const char *);
size_t strxfrm(char *, const char *, size_t);
size_t strlcpy(char *, const char *, size_t);
errno_t memset_s(void *s, size_t smax, int c, size_t n);




;
;




char * strndup(const char *, size_t);
size_t strnlen(const char *, size_t);
int consttime_memequal(const void *b1, const void *b2, size_t len);




int bcmp(const void *, const void *, size_t);
void bcopy(const void *, void *, size_t);
void bzero(void *, size_t);
char * index(const char *, int);
void * mempcpy(void *, const void *, size_t);
char * rindex(const char *, int);
char * stpncpy(char *dest, const char *src, size_t n);
int strcasecmp(const char *, const char *);
int strncasecmp(const char *, const char *, size_t);

int ffs(int);
int ffsl(long int);
int ffsll(long long int);

char * strtok_r(char *, const char *, char **);
int strerror_r(int, char *, size_t);




;
;


# 50 "secure_enclave.c" 2
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdio.h" 1
# 63 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdio.h"


int snprintf(char *, size_t, const char *, ...) __attribute__((__format__ (printf, 3, 4)));
int vsnprintf(char *, size_t, const char *, __va_list) __attribute__((__format__ (printf, 3, 0)));
# 92 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdio.h"

# 51 "secure_enclave.c" 2


# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/stdbool.h" 1
# 54 "secure_enclave.c" 2
# 1 "domain_parameters.h" 1

typedef struct point_s* point;
struct point_s
{
 mpz_t x;
 mpz_t y;
 _Bool infinity;
};


typedef struct domain_parameters_s* domain_parameters;
struct domain_parameters_s
{
 char* name;
 mpz_t p;
 mpz_t a;
 mpz_t b;
 point G;
 mpz_t n;
 mpz_t h;
};


domain_parameters domain_parameters_init();


void domain_parameters_set_name(domain_parameters curve, char* name);


void domain_parameters_set_ui(domain_parameters curve,
        char* name,
        unsigned long int p,
        unsigned long int a,
        unsigned long int b,
        unsigned long int Gx,
        unsigned long int Gy,
        unsigned long int n,
        unsigned long int h);


void domain_parameters_set_hex(domain_parameters curve, char* name, char* p, char* a, char* b, char* Gx, char* Gy, char* n, char* h);


void domain_parameters_clear(domain_parameters curve);
# 55 "secure_enclave.c" 2
# 1 "point.h" 1


point point_init();


void point_clear(point p);


void point_at_infinity(point p);


void point_inverse(point R, point P, domain_parameters curve);


void point_print(point p);


void point_set_hex(point p, char *x, char *y);


void point_set_ui(point p, unsigned long int x, unsigned long int y);


void point_addition(point result, point P, point Q, domain_parameters curve);


void point_doubling(point R, point P, domain_parameters curve);


void point_multiplication(point R, mpz_t multiplier, point P, domain_parameters curve);


void point_set_str(point p, char *x, char *y, int base);


_Bool point_cmp(point P, point Q);



void point_decompress(point P, char* zPoint, domain_parameters curve);



char* point_compress(point P);


void point_copy(point R, point P);


void point_set(point R, point P);
# 56 "secure_enclave.c" 2
# 1 "signature.h" 1


struct signature_s
{
 mpz_t r;
 mpz_t s;
};

typedef struct signature_s* signature;


signature signature_init();


void signature_set_str(signature sig, char *r, char *s, int base);


void signature_set_hex(signature sig, char *r, char *s);


void signature_set_ui(signature sig, unsigned long int r, unsigned long int s);


void signature_print(signature sig);


void signature_copy(signature R, signature sig);


_Bool signature_cmp(signature sig1, signature sig2);


void signature_free(signature sig);


void signature_generate_key(point public_key, mpz_t private_key, domain_parameters curve);


void signature_sign(signature sig, mpz_t message, mpz_t private_key, domain_parameters curve);


_Bool signature_verify(mpz_t message, signature sig, point public_key, domain_parameters curve);
# 57 "secure_enclave.c" 2
# 1 "curves.h" 1

typedef enum { secp112r1 = 0,

    secp128r1,

    secp160k1,
    secp160r1,
    secp160r2,
    secp192k1,
    secp192r1,
    secp224k1,
    secp224r1,
    secp256k1,
    secp256r1,
    secp384r1,
    secp521r1 } curve_list;





void domain_parameters_load_curve(domain_parameters out, curve_list curve);
# 58 "secure_enclave.c" 2





# 1 "../sgxwallet_common.h" 1
# 10 "../sgxwallet_common.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/unistd.h" 1
# 39 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/unistd.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/types.h" 1
# 44 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/types.h"
# 1 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/endian.h" 1
# 45 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/types.h" 2

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

typedef unsigned char unchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
# 107 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/types.h"
typedef __uint8_t u_int8_t;
typedef __uint16_t u_int16_t;
typedef __uint32_t u_int32_t;
typedef __uint64_t u_int64_t;
# 120 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/sys/types.h"
typedef __ssize_t ssize_t;




typedef __off_t off_t;
# 40 "/home/kladko/sgxwallet/sgx-sdk-build/sgxsdk/include/tlibc/unistd.h" 2



void * sbrk(intptr_t);




;
;
;
;
;
;




# 11 "../sgxwallet_common.h" 2
# 64 "secure_enclave.c" 2


void *(*gmp_realloc_func)(void *, size_t, size_t);

void *(*oc_realloc_func)(void *, size_t, size_t);

void (*gmp_free_func)(void *, size_t);

void (*oc_free_func)(void *, size_t);

void *reallocate_function(void *, size_t, size_t);

void free_function(void *, size_t);


void tgmp_init() {
    oc_realloc_func = &reallocate_function;
    oc_free_func = &free_function;

    __gmp_get_memory_functions(((void *)0), &gmp_realloc_func, &gmp_free_func);
    __gmp_set_memory_functions(((void *)0), oc_realloc_func, oc_free_func);
}

void free_function(void *ptr, size_t sz) {
    if (sgx_is_within_enclave(ptr, sz))
        gmp_free_func(ptr, sz);
    else {
        sgx_status_t status;

        status = oc_free(ptr, sz);
        if (status != SGX_SUCCESS)
            abort();
    }
}

void *reallocate_function(void *ptr, size_t osize, size_t nsize) {
    uint64_t nptr;
    sgx_status_t status;

    if (sgx_is_within_enclave(ptr, osize)) {
        return gmp_realloc_func(ptr, osize, nsize);
    }

    status = oc_realloc(&nptr, ptr, osize, nsize);
    if (status != SGX_SUCCESS)
        abort();







    if (!sgx_is_outside_enclave((void *) ptr, nsize))
        abort();

    return (void *) nptr;
}

void trustedEMpzAdd(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void trustedEMpzMul(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void trustedEMpzDiv(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void trustedEMpfDiv(mpf_t *c_un, mpf_t *a_un, mpf_t *b_un) {}


void trustedGenerateEcdsaKey(int *err_status, char *err_string,
                        uint8_t *encrypted_key, uint32_t *enc_len, char * pub_key_x, char * pub_key_y) {

  domain_parameters curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  mpz_t skey;
  __gmpz_init(skey);



  point Pkey = point_init();

  gmp_randstate_t state;
  __gmp_randinit_mt(state);

  __gmpz_urandomm(skey, state, curve->p);

  signature_generate_key(Pkey, skey, curve);

  int len = __gmpz_sizeinbase (Pkey->x, 10) + 2;

  char arr_x[len];
  char* px = __gmpz_get_str(arr_x, 10, Pkey->x);
  snprintf(err_string, 1024, "arr=%p px=%p\n", arr_x, px);
  strncpy(pub_key_x, arr_x, 1024);


  char arr_y[__gmpz_sizeinbase (Pkey->y, 10) + 2];
  char* py = __gmpz_get_str(arr_y, 10, Pkey->y);
  strncpy(pub_key_y, arr_y, 1024);

  char skey_str[__gmpz_sizeinbase (skey, 10) + 2];
  char* s = __gmpz_get_str(skey_str, 10, skey);

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, 32);

  sgx_status_t status = sgx_seal_data(0, ((void *)0), 32, (uint8_t *)skey_str, sealedLen,(sgx_sealed_data_t*)encrypted_key);
  if( status != SGX_SUCCESS) {
    snprintf(err_string, 1024,"seal ecsdsa private key failed");
    return;
  }

  *enc_len = sealedLen;
  __gmpz_clear(skey);
  __gmp_randclear(state);
  domain_parameters_clear(curve);
}


void trustedEncryptKey(int *err_status, char *err_string, char *key,
                 uint8_t *encrypted_key, uint32_t *enc_len) {

    init();

    *err_status = -1;

    memset(err_string, 0, 1024);

    checkKey(err_status, err_string, key);

    if (*err_status != 0) {
        snprintf(err_string + strlen(err_string), 1024, "check_key failed");
        return;
    }

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, 128);



    if (sealedLen > 1024) {
        *err_status = -6;
        snprintf(err_string, 1024, "sealedLen > MAX_ENCRYPTED_KEY_LENGTH");
        return;
    }


    memset(encrypted_key, 0, 1024);

    if (sgx_seal_data(0, ((void *)0), 128, (uint8_t *) key, sealedLen, (sgx_sealed_data_t *) encrypted_key) !=
        SGX_SUCCESS) {
        *err_status = -7;
        snprintf(err_string, 1024, "SGX seal data failed");
        return;
    }

    *enc_len = sealedLen;

    char decryptedKey[1024];
    memset(decryptedKey, 0, 1024);

    trustedDecryptKey(err_status, err_string, encrypted_key, sealedLen, decryptedKey);

    if (*err_status != 0) {
        snprintf(err_string + strlen(err_string), 1024, ":trustedDecryptKey failed");
        return;
    }

    uint64_t decryptedKeyLen = strnlen(decryptedKey, 128);

    if (decryptedKeyLen == 128) {
        snprintf(err_string, 1024, "Decrypted key is not null terminated");
        return;
    }


    *err_status = -8;

    if (strncmp(key, decryptedKey, 128) != 0) {
        snprintf(err_string, 1024, "Decrypted key does not match original key");
        return;
    }

    *err_status = 0;
}

void trustedDecryptKey(int *err_status, char *err_string, uint8_t *encrypted_key,
                 uint32_t enc_len, char *key) {

    init();


    uint32_t decLen;

    *err_status = -9;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_key, ((void *)0), 0, (uint8_t *) key, &decLen);

    if (status != SGX_SUCCESS) {
        snprintf(err_string, 1024, "sgx_unseal_data failed with status %d", status);
        return;
    }


    if (decLen != 128) {
        snprintf(err_string, 1024, "decLen != MAX_KEY_LENGTH");
        return;
    }

    *err_status = -10;


    uint64_t keyLen = strnlen(key, 128);


    if (keyLen == 128) {
        snprintf(err_string, 1024, "Key is not null terminated");
        return;
    }



    for (int i = keyLen; i < 128; i++) {
        if (key[i] != 0) {
            snprintf(err_string, 1024, "Unpadded key");
            return;
        }
    }

    *err_status = 0;
    return;

}


void trustedBlsSignMessage(int *err_status, char *err_string, uint8_t *encrypted_key,
                      uint32_t enc_len, char *_hashX,
                      char *_hashY, char *signature) {



    char key[1024];
    char* sig = (char*) calloc(1024, 1);

    init();


    trustedDecryptKey(err_status, err_string, encrypted_key, enc_len, key);

    if (*err_status != 0) {
        return;
    }

    enclave_sign(key, _hashX, _hashY, sig);

    strncpy(signature, sig, 1024);

    if (strnlen(signature, 1024) < 10) {
        *err_status = -1;
        return;
    }


}

void trustedGenDkgSecret (int *err_status, char *err_string, uint8_t *encrypted_dkg_secret, uint32_t* enc_len, size_t _t){

  char* dkg_secret = (char*)malloc(1250);

  gen_dkg_poly(dkg_secret, _t);

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, 1250);

  sgx_status_t status = sgx_seal_data(0, ((void *)0), 1250, (uint8_t*)dkg_secret, sealedLen,(sgx_sealed_data_t*)encrypted_dkg_secret);

  if( status != SGX_SUCCESS) {
    snprintf(err_string, 1024,"SGX seal data failed");
  }

  *enc_len = sealedLen;
  free(dkg_secret);
}

void trustedDecryptDkgSecret (int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint8_t* decrypted_dkg_secret, uint32_t enc_len){



  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_dkg_secret, ((void *)0), 0, decrypted_dkg_secret, &enc_len);

  if (status != SGX_SUCCESS) {
    snprintf(err_string, 1024,"sgx_unseal_data failed with status %d", status);
    return;
  }
}

void trustedGetSecretShares(int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint32_t enc_len, char* secret_shares,
    unsigned _t, unsigned _n){
  char* decrypted_dkg_secret = (char*)malloc(2000);
  trustedDecryptDkgSecret(err_status, err_string, (uint8_t*)encrypted_dkg_secret, decrypted_dkg_secret, enc_len);
  calc_secret_shares(decrypted_dkg_secret, secret_shares, _t, _n);
}

void trustedGetPublicShares(int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint32_t enc_len, char* public_shares,
                       unsigned _t, unsigned _n){
    char* decrypted_dkg_secret = (char*)malloc(2000);
    trustedDecryptDkgSecret(err_status, err_string, (uint8_t*)encrypted_dkg_secret, decrypted_dkg_secret, enc_len);
    calc_public_shares(decrypted_dkg_secret, public_shares, _t);
}


typedef struct signature_s* signature;
struct signature_s
{
  mpz_t r;
  mpz_t s;
};

void trustedEcdsaSign(int *err_status, char *err_string, uint8_t *encrypted_key,
                        uint32_t dec_len, unsigned char* hash, char * signature, int test_len) {

  domain_parameters curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  char skey[32];

  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_key, ((void *)0), 0, skey, &dec_len);

  if (status != SGX_SUCCESS) {
    snprintf(err_string, 1024,"sgx_unseal_data failed with status %d", status);
    return;
  }

  memcpy(err_string, skey, 1024);

  mpz_t skey_mpz;
  __gmpz_init(skey_mpz);
  __gmpz_set_str(skey_mpz, skey, 10);

  mpz_t msg_mpz;
  __gmpz_init(msg_mpz);
  __gmpz_set_str(msg_mpz, skey, 10);

  signature sig;



  domain_parameters_clear(curve);
}
