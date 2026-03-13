// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Test: realloc generates realloc_free + realloc events
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
	void *p = malloc(64);

	for (int i = 0; i < 10; i++) {
		p = realloc(p, 64 * (i + 2));
		usleep(200);
	}

	free(p);
	return 0;
}
