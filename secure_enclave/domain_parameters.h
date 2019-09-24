/*Type that represents a point*/
typedef struct point_s* point;
struct point_s
{
	mpz_t x;
	mpz_t y;
	bool infinity;
};

/*Type that represents a curve*/
typedef struct domain_parameters_s* domain_parameters;
struct domain_parameters_s
{
	char* name;
	mpz_t p;	//Prime
	mpz_t a;	//'a' parameter of the elliptic curve
	mpz_t b;	//'b' parameter of the elliptic curve
	point G;	//Generator point of the curve, also known as base point.
	mpz_t n;
	mpz_t h;
};

/*Initialize a curve*/
domain_parameters domain_parameters_init();

/*Sets the name of a curve*/
void domain_parameters_set_name(domain_parameters curve, char* name);

/*Set domain parameters from decimal unsigned long ints*/
void domain_parameters_set_ui(domain_parameters curve,
								char* name,
								unsigned long int p,
								unsigned long int a,
								unsigned long int b,
								unsigned long int Gx,
								unsigned long int Gy,
								unsigned long int n,
								unsigned long int h);

/*Set domain parameters from hexadecimal string*/
void domain_parameters_set_hex(domain_parameters curve, char* name, char* p, char* a, char* b, char* Gx, char* Gy, char* n, char* h);

/*Release memory*/
void domain_parameters_clear(domain_parameters curve);

