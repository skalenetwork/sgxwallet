//
// Created by kladko on 9/2/19.
//


#ifndef SGXWALLET_SERVERINIT_H
#define SGXWALLET_SERVERINIT_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC void init_all();

EXTERNC void init_daemon();

EXTERNC  void init_enclave();


#endif //SGXWALLET_SERVERINIT_H
