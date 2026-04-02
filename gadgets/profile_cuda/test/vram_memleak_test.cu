// SPDX-License-Identifier: Apache-2.0
/* CUDA VRAM Memory Leak Test
 *
 * Minimal CUDA program that deliberately triggers all four VRAM
 * detection types in IG's profile_cuda gadget:
 *
 *   1. Leaked allocation   — cuMemAlloc + use + no cuMemFree
 *   2. Unused allocation   — cuMemAlloc + cuMemFree, never accessed
 *   3. Exception-path leak — cuMemAlloc, never used, never freed
 *   4. Fragmentation       — force cuMemAlloc failure (optional)
 *
 * Build: nvcc -o vram_memleak_test vram_memleak_test.cu -lcuda
 * Run:   ./vram_memleak_test
 */

#include <cuda.h>
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK_CUDA(call) do {                                         \
    cudaError_t err = (call);                                         \
    if (err != cudaSuccess) {                                         \
        fprintf(stderr, "CUDA error at %s:%d: %s\n",                 \
                __FILE__, __LINE__, cudaGetErrorString(err));         \
        /* don't exit — we want to continue for exception-path */     \
    }                                                                 \
} while(0)

/* Simple kernel that reads/writes device memory (marks alloc as "used") */
__global__ void touch_memory(float *ptr, int n) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n)
        ptr[idx] = ptr[idx] + 1.0f;
}

int main(int argc, char **argv) {
    printf("=== VRAM Memory Leak Test ===\n");

    /* Initialize CUDA */
    CHECK_CUDA(cudaSetDevice(0));

    float *leaked_ptr = NULL;
    float *unused_ptr = NULL;
    float *exception_ptr = NULL;
    float *normal_ptr = NULL;
    size_t leaked_size = 4 * 1024 * 1024;      /* 4 MB */
    size_t unused_size = 2 * 1024 * 1024;       /* 2 MB */
    size_t exception_size = 1 * 1024 * 1024;    /* 1 MB */
    size_t normal_size = 1 * 1024 * 1024;       /* 1 MB */
    int n;

    /*
     * 1. LEAKED ALLOCATION — alloc, use, but never free
     *    IG should detect this in leaked_allocs datasource.
     */
    printf("[1] Leaked allocation: %zu bytes... ", leaked_size);
    CHECK_CUDA(cudaMalloc((void**)&leaked_ptr, leaked_size));
    CHECK_CUDA(cudaMemset(leaked_ptr, 0, leaked_size));
    n = leaked_size / sizeof(float);
    touch_memory<<<(n + 255) / 256, 256>>>(leaked_ptr, n);
    CHECK_CUDA(cudaDeviceSynchronize());
    printf("allocated + used at %p (NOT freeing)\n", leaked_ptr);
    /* deliberately NOT calling cudaFree(leaked_ptr) */

    /*
     * 2. UNUSED ALLOCATION — alloc, then free, but never access
     *    IG should detect this in unused_allocs datasource.
     */
    printf("[2] Unused allocation: %zu bytes... ", unused_size);
    CHECK_CUDA(cudaMalloc((void**)&unused_ptr, unused_size));
    printf("allocated at %p (freeing without use)\n", unused_ptr);
    CHECK_CUDA(cudaFree(unused_ptr));
    printf("    freed (never accessed)\n");

    /*
     * 3. EXCEPTION-PATH ALLOCATION — alloc, never use, never free
     *    Simulates allocation in an error-handling path that leaks.
     *    IG should detect this in exception_path_allocs datasource.
     */
    printf("[3] Exception-path allocation: %zu bytes... ", exception_size);
    CHECK_CUDA(cudaMalloc((void**)&exception_ptr, exception_size));
    printf("allocated at %p (NOT using, NOT freeing)\n", exception_ptr);
    /* deliberately NOT using or freeing exception_ptr */

    /*
     * 4. NORMAL ALLOCATION — alloc, use, free (baseline, no detection)
     */
    printf("[4] Normal allocation (control): %zu bytes... ", normal_size);
    CHECK_CUDA(cudaMalloc((void**)&normal_ptr, normal_size));
    CHECK_CUDA(cudaMemset(normal_ptr, 0, normal_size));
    n = normal_size / sizeof(float);
    touch_memory<<<(n + 255) / 256, 256>>>(normal_ptr, n);
    CHECK_CUDA(cudaDeviceSynchronize());
    CHECK_CUDA(cudaFree(normal_ptr));
    printf("allocated, used, freed at %p (clean)\n", normal_ptr);

    /*
     * 5. FRAGMENTATION TRIGGER (optional) — attempt to alloc more than
     *    available VRAM. This should generate a fragmentation_event
     *    if the net_allocated is much less than GPU total.
     *    We try a huge allocation that should fail.
     */
    printf("[5] Fragmentation trigger: attempting 999 GB alloc... ");
    float *frag_ptr = NULL;
    cudaError_t frag_err = cudaMalloc((void**)&frag_ptr, (size_t)999 * 1024 * 1024 * 1024);
    if (frag_err != cudaSuccess) {
        printf("failed as expected (error: %s)\n", cudaGetErrorString(frag_err));
    } else {
        printf("unexpectedly succeeded, freeing\n");
        cudaFree(frag_ptr);
    }

    printf("\n=== Test complete ===\n");
    printf("Expected detections:\n");
    printf("  leaked_allocs:          1 (4 MB) — ptr at %p\n", leaked_ptr);
    printf("  unused_allocs:          1 (2 MB)\n");
    printf("  exception_path_allocs:  1 (1 MB) — ptr at %p\n", exception_ptr);
    printf("  fragmentation_events:   1 (999 GB request failed)\n");
    printf("  normal (no detection):  1 (1 MB) — properly freed\n");

    return 0;
}
