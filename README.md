# Demo Programs for the GNU\* Multiple Precision Arithmetic Library\* for Intel&reg; Software Guard Extensions

These two programs demonstrate how to use the Intel SGX build of the GMP library. For more information about this project, see the accompanying article "[Building the GNU\* Multiple Precision\* Arithmetic Library for Intel® Software Guard Extensions](https://software.intel.com/en-us/articles/building-the-gnu-multiple-precision-library-for-intel-software-guard-extensions)".

## Prerequisites

To build and run these demo applications, you'll need the following:

* The [GNU Multiple Precision Arithmetic Library for Intel Software Guard Extensions](https://github.com/intel/sgx-gmp)
  * both the Intel SGX and "stock" builds of this library are required
  * both builds can be produced from the above
* The [Intel SGX SDK](https://github.com/intel/linux-sgx)
* Intel SGX capable hardware

These applications have been tested on:

* Ubuntu\* Linux\* 16.04, 18.04
* CentOS\* Linux 7.4

## Building

Configure the distribution by running the `configure` script. You'll need to specify the location of the standard and Intel SGX builds of GMP:

```
  --with-gmpdir=PATH           specify the libgmp directory
  --with-trusted-gmpdir=PATH   the trusted libgmp directory (default: gmp directory)
```

If both builds of the library are installed to the same directory, you can just specify `--with-gmpdir=PATH`.

To compile the applications, run `make`.

## Running the Demo Programs

### sgxgmpmath

This program takes two numbers on the command line, and then calls into the enclave to perform addition, multiplication, integer division, and floating point division. Each of these results is printed to stdout.

Usage is:

<pre>

sgxgmpmath <i>num1</i> <i>num2</i>
</pre>

Sample output is shown below:

```
$ ./sgxgmpmath 12345678901234567890 9876543210
Enclave launched
libtgmp initialized
iadd : 12345678901234567890 + 9876543210 = 12345678911111111100

imul : 12345678901234567890 * 9876543210 = 121932631124828532111263526900

idiv : 12345678901234567890 / 9876543210 = 1249999988

fdiv : 12345678901234567890 / 9876543210 = 1249999988.734374999000
```

### sgxgmppi

This program is a more advanced example of using the GMP library in an enclave, and it exercises several of GMP’s capabilities including factorials, exponentiation, n-roots, floating point division, and bits of precision. It makes an ECALL to calculate the value of pi to the specified number of digits using the [Chudnovsky algorithm](https://en.wikipedia.org/wiki/Chudnovsky_algorithm) and places the value in a GMP variable that is passed to the ECALL as a parameter.
Usage is:

<pre>
   sgxgmppi <i>ndigits</i>
</pre>

Note that the implementation of Chudnovsky’s algorithm in this demo application emphasizes clarity over performance.

Sample output:

```
$ ./sgxgmppi 1000
Enclave launched
libtgmp initialized
pi : 3.141592653589793238462643383279502884197169399375105820974944592307816
4062862089986280348253421170679821480865132823066470938446095505822317253594
0812848111745028410270193852110555964462294895493038196442881097566593344612
8475648233786783165271201909145648566923460348610454326648213393607260249141
2737245870066063155881748815209209628292540917153643678925903600113305305488
2046652138414695194151160943305727036575959195309218611738193261179310511854
8074462379962749567351885752724891227938183011949129833673362440656643086021
3949463952247371907021798609437027705392171762931767523846748184676694051320
0056812714526356082778577134275778960917363717872146844090122495343014654958
5371050792279689258923542019956112129021960864034418159813629774771309960518
7072113499999983729780499510597317328160963185950244594553469083026425223082
5334468503526193118817101000313783875288658753320838142061717766914730359825
3490428755468731159562863882353787593751957781857780532171226806613001927876
6111959092164201989
```
# sgxd
