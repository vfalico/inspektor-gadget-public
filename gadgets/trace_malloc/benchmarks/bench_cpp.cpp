// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Benchmark: rapid new/delete + new[]/delete[] cycle
#include <cstdio>

#define ITERATIONS 100000

int main() {
	// scalar new/delete
	for (int i = 0; i < ITERATIONS; i++) {
		int *p = new int(i);
		delete p;
	}

	// array new[]/delete[]
	for (int i = 0; i < ITERATIONS; i++) {
		int *arr = new int[64];
		delete[] arr;
	}

	return 0;
}
