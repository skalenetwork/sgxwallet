//
// Created by kladko on 10/1/19.
//

#ifndef SGXD_DRIVE_KEY_DKG_H
#define SGXD_DRIVE_KEY_DKG_H

//void gen_session_keys(mpz_t skey, char* pub_key);
void gen_session_key(char* skey, char* pub_keyB, char* common_key);

void session_key_recover(const char *skey_str, const char* sshare, char* common_key);

void xor_encrypt(char* key, char* message, char* cypher);

void xor_decrypt(char* key, char* cypher, char* message);


#endif //SGXD_DRIVE_KEY_DKG_H
