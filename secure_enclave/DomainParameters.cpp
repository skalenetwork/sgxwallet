/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

    @file domain_parameters.c
    @author Stan Kladko
    @date 2019
*/

#define SAFE_FREE(__X__)                                                       \
  if (__X__) {                                                                 \
    free(__X__);                                                               \
    __X__ = NULL;                                                              \
  }
#define SAFE_DELETE(__X__)                                                     \
  if (__X__) {                                                                 \
    delete (__X__);                                                            \
    __X__ = NULL;                                                              \
  }
#define SAFE_CHAR_BUF(__X__, __Y__)                                            \
  ;                                                                            \
  char __X__[__Y__];                                                           \
  memset(__X__, 0, __Y__);

#ifdef USER_SPACE
#include <gmp.h>
#else
#include <../tgmp-build/include/sgx_tgmp.h>
#endif

#include "EnclaveCommon.h"
#include "Point.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "DomainParameters.h"

#define CHECK_ARG_ABORT(_EXPRESSION_)                                          \
  if (!(_EXPRESSION_)) {                                                       \
    abort();                                                                   \
  }

/*Initialize a curve*/
domain_parameters domain_parameters_init() {

  domain_parameters curve;
  curve = (domain_parameters)calloc(sizeof(struct domain_parameters_s), 1);

  CHECK_ARG_ABORT(curve);

  // Initialize all members
  mpz_init(curve->p);
  mpz_init(curve->a);
  mpz_init(curve->b);
  mpz_init(curve->n);
  mpz_init(curve->h);

  curve->G = point_init();

  CHECK_ARG_ABORT(curve->G);

  return curve;
}

/*Sets the name of a curve*/
void domain_parameters_set_name(domain_parameters curve, char *name) {

  CHECK_ARG_ABORT(name);
  int len = strlen(name);
  curve->name = (char *)calloc(sizeof(char) * (len + 1), 1);
  curve->name[len] = '\0';
  strncpy(curve->name, name, len + 1);
}

/*Set domain parameters from decimal unsigned long ints*/
void domain_parameters_set_ui(domain_parameters curve, char *name,
                              unsigned long int p, unsigned long int a,
                              unsigned long int b, unsigned long int Gx,
                              unsigned long int Gy, unsigned long int n,
                              unsigned long int h) {

  CHECK_ARG_ABORT(name);

  domain_parameters_set_name(curve, name);
  mpz_set_ui(curve->p, p);
  mpz_set_ui(curve->a, a);
  mpz_set_ui(curve->b, b);
  point_set_ui(curve->G, Gx, Gy);
  mpz_set_ui(curve->n, n);
  mpz_set_ui(curve->h, h);
}

/*Set domain parameters from hexadecimal string*/
void domain_parameters_set_hex(domain_parameters curve, char *name, char *p,
                               char *a, char *b, char *Gx, char *Gy, char *n,
                               char *h) {

  CHECK_ARG_ABORT(name);
  CHECK_ARG_ABORT(p);
  CHECK_ARG_ABORT(a);
  CHECK_ARG_ABORT(b);
  CHECK_ARG_ABORT(Gx);
  CHECK_ARG_ABORT(Gy);
  CHECK_ARG_ABORT(n);
  CHECK_ARG_ABORT(h);

  domain_parameters_set_name(curve, name);
  mpz_set_str(curve->p, p, 16);
  mpz_set_str(curve->a, a, 16);
  mpz_set_str(curve->b, b, 16);
  point_set_hex(curve->G, Gx, Gy);
  mpz_set_str(curve->n, n, 16);
  mpz_set_str(curve->h, h, 16);
}

/*Release memory*/
void domain_parameters_clear(domain_parameters curve) {

  if (!curve)
    return;

  mpz_clear(curve->p);
  mpz_clear(curve->a);
  mpz_clear(curve->b);
  point_clear(curve->G);
  mpz_clear(curve->n);
  mpz_clear(curve->h);
  SAFE_FREE(curve->name);
  free(curve);
}
