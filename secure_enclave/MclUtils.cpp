#include "MclUtils.h"
#include <sgx_trts.h>

// Forward declaration for enclave printing (defined in secure_enclave.c)
extern "C" void oc_printf(const char *str);

// mcl expects: uint32_t readFunc(void* self, void* buf, uint32_t byteSize)
static uint32_t mcl_sgx_rand(void *self, void *buf, uint32_t byteSize) {
  (void)self;
  sgx_status_t status = sgx_read_rand((unsigned char *)buf, byteSize);
  return (status == SGX_SUCCESS) ? byteSize : 0;
}

bool isG2(const G2 &point) { return !point.isZero() && point.isValid(); }

Fr power(const Fr &base, long exp) {
  Fr res;
  mcl::bn::Fr::pow(res, base, exp);
  return res;
}

// Generate a random Fr element using SGX's sgx_read_rand directly.
// This bypasses MCL's RandGen which has C++ static initialization issues in
// SGX. Matches how libff implemented bigint::randomize() for SGX.
void setRandomFr(Fr &fr) {
  constexpr size_t FR_BYTE_SIZE = 32;
  uint8_t buf[FR_BYTE_SIZE];

  // Generate random bytes using SGX's hardware RNG
  sgx_status_t status = sgx_read_rand(buf, FR_BYTE_SIZE);
  if (status != SGX_SUCCESS) {
    // In case of failure, zero out the Fr
    fr.clear();
    return;
  }

  // Use setArrayMask which handles modular reduction correctly:
  // It masks high bits to fit within field order and reduces if still >= p
  fr.setArrayMask(buf, FR_BYTE_SIZE);
}

void initMcl() {
  const mcl::bn::CurveParam cp = mcl::bn::BN_SNARK1;
  bool b = false;
  mcl::bn::initPairing(&b, cp);
  if (!b) {
    oc_printf("***ENCLAVE_LOG***:initMcl: mcl::bn::initPairing FAILED!\n");
  } else {
    oc_printf("***ENCLAVE_LOG***:initMcl: mcl::bn::initPairing succeeded\n");
  }
  // Set custom random generator for SGX (may still be used by other MCL
  // functions)
  mcl::fp::RandGen::setRandFunc(nullptr, mcl_sgx_rand);
}
