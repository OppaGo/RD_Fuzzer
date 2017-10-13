#pragma once
#include <stdio.h>
#include "default.h"

FILE* OpenLogger();
void CloseLogger(FILE* fp);
