
/*Calculate R = a^k mod P, using repeated square-and-multiply algorithm
 *Handbook of applied cryptography: Algorithm 2.143. */
void number_theory_exp_modp(mpz_t R, mpz_t a, mpz_t k, mpz_t P);

/*Calculates R² mod P = a, the squareroot of a mod P
 *Handbook of applied cryptography: Algorithm 3.36, 3.37 and 3.34 */
void number_theory_squareroot_modp(mpz_t R, mpz_t a, mpz_t P);

/*Calculate the multiplicative inverse of a mod p, using the extended euclidean algorithm
 *Handbook of applied cryptography: Algorithm 2.107
 *http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm */
void number_theory_inverse(mpz_t R, mpz_t A, mpz_t P);

/*Calculates the legendre symbol of a and p
 *Handbook of applied cryptography: Fact 2.146 */
int number_theory_legendre(mpz_t a, mpz_t p);

/*Calculate R = a^k mod P, wraps around number_theory_exp_modp() */
void number_theory_exp_modp_ui(mpz_t R, mpz_t a, unsigned long int k, mpz_t P);

/*Use GMP number theory implementation instead of the algorithms I've implemented.
 *My algorithms should be bugfree they've been extensively tested, but they far slower
 *than GMP implementations. GMP has no implementation of squareroot, but all the other
 *functions are implemented in GMP. Set 1 to use GMP, 0 to use my implementation. */
#define EXTERNAL_NUMBER_THEORY_IMPLEMENTATION 0
