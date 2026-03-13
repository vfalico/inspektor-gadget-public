// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Test: C++ new/delete and new[]/delete[] operators
#include <cstdio>
#include <unistd.h>

int main() {
	// scalar new/delete
	for (int i = 0; i < 5; i++) {
		int *p = new int(42);
		delete p;
		usleep(200);
	}

	// array new[]/delete[]
	for (int i = 0; i < 5; i++) {
		int *arr = new int[100];
		delete[] arr;
		usleep(200);
	}

	return 0;
}
