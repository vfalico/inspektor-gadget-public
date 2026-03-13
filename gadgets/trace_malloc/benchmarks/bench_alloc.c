// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Benchmark: rapid malloc/free cycle (C only)
#include <stdio.h>
#include <stdlib.h>

#define ITERATIONS 100000

int main(void) {
	for (int i = 0; i < ITERATIONS; i++) {
		void *p = malloc(256);
		if (!p)
			return 1;
		free(p);
	}
	return 0;
}
