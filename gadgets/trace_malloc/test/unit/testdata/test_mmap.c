// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Test: mmap/munmap events
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
	for (int i = 0; i < 10; i++) {
		size_t sz = 4096 * (i + 1);
		void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			return 1;
		munmap(p, sz);
		usleep(200);
	}
	return 0;
}
