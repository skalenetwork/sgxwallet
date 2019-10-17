//
// Created by kladko on 10/1/19.
//

#ifndef SGXD_DRIVE_KEY_DKG_H
#define SGXD_DRIVE_KEY_DKG_H

//void gen_session_keys(mpz_t skey, char* pub_key);
void gen_session_key(char* skey, char* pub_keyB, char* common_key);

void xor_encrypt(char* key, char* message, char* cypher);


#endif //SGXD_DRIVE_KEY_DKG_H
