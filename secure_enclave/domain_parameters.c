#include <../tgmp-build/include/sgx_tgmp.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "domain_parameters.h"
#include "point.h"

/*Initialize a curve*/
domain_parameters domain_parameters_init()
{
	domain_parameters curve;
	curve = malloc(sizeof(struct domain_parameters_s));

	//Initialize all members
	mpz_init(curve->p);
	mpz_init(curve->a);
	mpz_init(curve->b);
	curve->G = point_init();
	mpz_init(curve->n);
	mpz_init(curve->h);

	return curve;
}

/*Sets the name of a curve*/
void domain_parameters_set_name(domain_parameters curve, char* name)
{
	int len = strlen(name);
	curve->name = (char*)malloc( sizeof(char) * (len+1) );
	curve->name[len] = '\0';
	strncpy(curve->name, name, len+1);
}

/*Set domain parameters from decimal unsigned long ints*/
void domain_parameters_set_ui(domain_parameters curve,
								char* name,
								unsigned long int p,
								unsigned long int a,
								unsigned long int b,
								unsigned long int Gx,
								unsigned long int Gy,
								unsigned long int n,
								unsigned long int h)
{
	domain_parameters_set_name(curve, name);
	mpz_set_ui(curve->p, p);
	mpz_set_ui(curve->a, a);
	mpz_set_ui(curve->b, b);
	point_set_ui(curve->G, Gx, Gy);
	mpz_set_ui(curve->n, n);
	mpz_set_ui(curve->h, h);
}

/*Set domain parameters from hexadecimal string*/
void domain_parameters_set_hex(domain_parameters curve, char* name, char* p, char* a, char* b, char* Gx, char* Gy, char* n, char* h)
{
	domain_parameters_set_name(curve, name);
	mpz_set_str(curve->p, p, 16);
	mpz_set_str(curve->a, a, 16);
	mpz_set_str(curve->b, b, 16);
	point_set_hex(curve->G, Gx, Gy);
	mpz_set_str(curve->n, n, 16);
	mpz_set_str(curve->h, h, 16);
}

/*Release memory*/
void domain_parameters_clear(domain_parameters curve)
{
	mpz_clear(curve->p);
	mpz_clear(curve->a);
	mpz_clear(curve->b);
	point_clear(curve->G);
	mpz_clear(curve->n);
	mpz_clear(curve->h);
	free(curve->name);
	free(curve);
}

