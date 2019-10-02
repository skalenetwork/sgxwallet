#include <stdio.h>
#include <stdlib.h>
#include <../tgmp-build/include/sgx_tgmp.h>
#include "random.h"

/*Seeds the random state with information from /dev/random
 *This may take time, but it's needed to ensure true randomness*/
void random_seeding(gmp_randstate_t r_state)
{
	//Open the random device for reading
	FILE* ran = fopen(RANDOM_DEVICE, "r");

	//input variables
	char i1, i2, i3, i4;

	//Read 4 bytes, cause that's the most we can put in an unsigned long int
	i1 = fgetc(ran);
	if(i1 == EOF)
		goto end;
	i2 = fgetc(ran);
	if(i2 == EOF)
		goto end;
	i3 = fgetc(ran);
	if(i3 == EOF)
		goto end;
	i4 = fgetc(ran);
	if(i4 == EOF)
		goto end;

	//abs() returns long (signed long), therefor there must be two, since DO NOT want to loose any randomness
	gmp_randseed_ui(r_state, (unsigned long int)abs(i1)* (unsigned long int)abs(i2*i3*i4));

	//Define end
	end:

	//Close file resources
	fclose(ran);
}


