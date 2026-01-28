#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <string>

// Convert decimal string to hexadecimal with padding
std::string convertDecToHex(const std::string& dec, int numBytes = 32);

#endif // HEX_UTILS_H
