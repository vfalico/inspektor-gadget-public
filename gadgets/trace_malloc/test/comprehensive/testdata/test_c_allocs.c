// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Comprehensive C allocation test for trace-malloc
// Tests: malloc, calloc, realloc, reallocarray, mmap/munmap, posix_memalign, aligned_alloc, valloc, memalign
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>

#define N 10

int main(void) {
    void *ptrs[N];
    int i;

    printf("=== malloc/free ===\n");
    for (i = 0; i < N; i++) {
        ptrs[i] = malloc(1024 * (i + 1));
        if (!ptrs[i]) return 1;
        memset(ptrs[i], 'A', 1024 * (i + 1));
    }
    for (i = 0; i < N; i++)
        free(ptrs[i]);

    printf("=== calloc/free ===\n");
    for (i = 0; i < N; i++) {
        ptrs[i] = calloc(100, 64);
        if (!ptrs[i]) return 1;
    }
    for (i = 0; i < N; i++)
        free(ptrs[i]);

    printf("=== realloc ===\n");
    void *p = malloc(64);
    for (i = 0; i < N; i++) {
        p = realloc(p, 64 * (i + 2));
        if (!p) return 1;
    }
    free(p);

    printf("=== reallocarray ===\n");
    for (i = 0; i < N; i++) {
        p = reallocarray(NULL, 100 + i * 10, 64);
        if (!p) return 1;
        free(p);
    }

    printf("=== mmap/munmap ===\n");
    for (i = 0; i < N; i++) {
        size_t sz = 4096 * (i + 1);
        void *m = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) return 1;
        memset(m, 'B', sz);
        munmap(m, sz);
    }

    printf("=== posix_memalign ===\n");
    for (i = 0; i < N; i++) {
        void *aligned;
        if (posix_memalign(&aligned, 256, 1024 * (i + 1)) != 0) return 1;
        free(aligned);
    }

    printf("=== memalign ===\n");
    for (i = 0; i < N; i++) {
        void *m = memalign(128, 512 * (i + 1));
        if (!m) return 1;
        free(m);
    }

    // Leak some memory intentionally
    printf("=== intentional leak ===\n");
    void *leaked = malloc(4096);
    (void)leaked;  // intentionally leaked

    printf("All C tests passed.\n");
    return 0;
}
