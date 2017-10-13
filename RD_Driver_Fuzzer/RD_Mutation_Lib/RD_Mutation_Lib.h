#pragma once

#ifdef RD_MUTATION_LIB_EXPORTS
#define RD_MUTATION_LIB_API __declspec(dllexport)
#else
#define RD_MUTATION_LIB_API __declspec(dllimport)
#endif

#include "random.h"

typedef void* PRDMutation;

extern "C" RD_MUTATION_LIB_API uint32 GenRandomValue(uint32 max);
extern "C" RD_MUTATION_LIB_API uint32 Mutation(char * data, uint32 maxsize);
