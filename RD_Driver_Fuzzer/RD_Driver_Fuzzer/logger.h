#pragma once
#include <stdio.h>
#include "default.h"

FILE* OpenLogger(const char* filename);
void CloseLogger(FILE* fp);
