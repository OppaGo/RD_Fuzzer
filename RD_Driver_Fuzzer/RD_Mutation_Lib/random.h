#pragma once
#include "default.h"

/*
* wellrandom
*/
void InitWELLRNG512a(uint32 *init);
double WELLRNG512a(void);


uint32 _GenRandomValue(uint32 max);
void _Byte_flip(char* data, const uint32 dsize);
uint32 _Mutation(char * data, uint32 maxsize);
