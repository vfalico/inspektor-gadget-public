// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Test program: 10 malloc/free pairs of 1024 bytes each
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
	void *ptrs[10];
	int i;

	for (i = 0; i < 10; i++) {
		ptrs[i] = malloc(1024);
		if (!ptrs[i])
			return 1;
		usleep(200);
	}
	for (i = 0; i < 10; i++) {
		free(ptrs[i]);
	}

	return 0;
}
