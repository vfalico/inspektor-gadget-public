// Reproducer: XID 31 (GPU memory page fault) via use-after-free.
// Allocate a 4-byte buffer, free it, then launch a kernel that writes far
// outside any valid allocation using the freed pointer.  The GPU MMU
// reports XID 31 for the offending process.
#include <cuda.h>
#include <stdio.h>
#include <unistd.h>

__global__ void wander(int *p)
{
	/* Write at a wildly out-of-range offset so the MMU cannot find it. */
	p[1024 * 1024] = 42;
}

int main(void)
{
	int *d = NULL;
	cudaError_t e;
	if ((e = cudaMalloc(&d, 4)) != cudaSuccess) {
		fprintf(stderr, "cudaMalloc: %s\n", cudaGetErrorString(e));
		return 1;
	}
	if ((e = cudaFree(d)) != cudaSuccess) {
		fprintf(stderr, "cudaFree: %s\n", cudaGetErrorString(e));
		return 1;
	}
	wander<<<1, 1>>>(d);
	e = cudaDeviceSynchronize();
	fprintf(stderr, "sync: %s\n", cudaGetErrorString(e));
	/* Keep the process alive briefly so the gadget has time to catch the
	 * XID event before PID recycling can confuse userspace. */
	sleep(2);
	return 0;
}
