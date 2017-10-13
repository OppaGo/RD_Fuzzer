#include "random.h"
#include <random>
#include <functional>

/*
* _GenRandomValue
*/
#define WELLRANDOMLONG(x) (uint32)((double)WELLRNG512a() * 1000000000) % x
#define WELLRANDOMLONG2(x) (uint32)((double)WELLRNG512a() * 1000000000)
uint32 _GenRandomValue(uint32 max)
{
	std::random_device rd;
	std::mt19937 engine(rd());
	std::uniform_int_distribution<int> distribution(0, max);
	auto generator = bind(distribution, engine);
	unsigned int init[16];
	for (int i = 0; i < 16; i++)
		init[i] = generator();
	InitWELLRNG512a(init);
	try {
		return WELLRANDOMLONG(max);
	}
	catch (const std::exception e) {
		return WELLRANDOMLONG2(max);
	}
}

/*
* ByteFlip
*/
void _Byte_flip(char* data, const uint32 dsize) {
	uint32 offset = _GenRandomValue(dsize);
	uint8 reverse_case = (uint8)_GenRandomValue(0x100);
	data[offset] ^= reverse_case;
}

/*
* _Mutation
*/
uint32 _Mutation(char * data, const uint32 dsize)
{
	uint32 Mutation_count = _GenRandomValue(dsize);
	for (uint32 i = 0; i < Mutation_count; i++)
		_Byte_flip(data, dsize);

	return(dsize);
}
