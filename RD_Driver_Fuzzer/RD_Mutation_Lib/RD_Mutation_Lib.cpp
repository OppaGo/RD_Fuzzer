#include "RD_Mutation_Lib.h"

extern "C" RD_MUTATION_LIB_API uint32 GenRandomValue(uint32 max)
{
	return _GenRandomValue(max);
}

extern "C" RD_MUTATION_LIB_API uint32 Mutation(char * data, uint32 maxsize)
{
	return _Mutation(data, maxsize);
}
