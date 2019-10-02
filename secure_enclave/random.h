
/*Seeds the random state with information from /dev/random
 *This may take time, but it's needed to ensure true randomness*/
void random_seeding(gmp_randstate_t r_state);

/*Operating system dependent random device, please use true random
 *Linux has /dev/random as true RNG and /dev/urandom as pseudo random device
 *Note: /dev/random may be slow, whereas /dev/urandom is not as secure*/
#define RANDOM_DEVICE "/dev/urandom"

/*Time spent reading from random device is not included in benchmark and other timings.
 *To see difference between real execution time and execution time use Unix "time" command*/
