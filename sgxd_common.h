//
// Created by kladko on 9/3/19.
//

#ifndef SGXD_SGXD_COMMON_H
#define SGXD_SGXD_COMMON_H

#define  MAX_KEY_LENGTH 128
#define  MAX_COMPONENT_LENGTH 80
#define  MAX_COMPONENT_HEX_LENGTH MAX_COMPONENT_LENGTH * 2
#define  MAX_ENCRYPTED_KEY_LENGTH 1024
#define  MAX_SIG_LEN 1024
#define  MAX_ERR_LEN 1024
#define SHA_256_LEN 32

#define ADD_ENTROPY_SIZE 32

inline int char2int(char _input) {
    if (_input >= '0' && _input <= '9')
        return _input - '0';
    if (_input >= 'A' && _input <= 'F')
        return _input - 'A' + 10;
    if (_input >= 'a' && _input <= 'f')
        return _input - 'a' + 10;
    return -1;
}



inline unsigned char *carray2Hex(const uint8_t *d, int _len) {
    unsigned char *hex = malloc(2 * _len);

    static char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for (int j = 0; j < _len; j++) {
        hex[j * 2] = hexval[((d[j] >> 4) & 0xF)];
        hex[j * 2 + 1] = hexval[(d[j]) & 0x0F];
    }

    return hex;
}


inline uint8_t* hex2carray(unsigned char * _hex, uint64_t *_bin_len) {

    uint64_t len = strlen((char*)_hex);


    if (len == 0 && len % 2 == 1)
        return  NULL;

    *_bin_len = len / 2;

    uint8_t* bin = malloc(len / 2);

    for (int i = 0; i < len / 2; i++) {
        int high = char2int((char)_hex[i * 2]);
        int low = char2int((char)_hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return NULL;
        }

        bin[i] = (uint8_t) (high * 16 + low);
    }

    return bin;
}


#endif //SGXD_SGXD_COMMON_H
