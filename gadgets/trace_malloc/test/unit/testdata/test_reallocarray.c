// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Test: reallocarray operations
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
	for (int i = 0; i < 10; i++) {
		void *p = reallocarray(NULL, 100, 64);
		if (!p)
			return 1;
		free(p);
		usleep(200);
	}
	return 0;
}
