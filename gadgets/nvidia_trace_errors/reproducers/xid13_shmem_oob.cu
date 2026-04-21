// Reproducer: candidate XID 13 (GR SW Notify / illegal shared-memory access).
//
// Declares a tiny shared-memory allocation (256 B) then writes far past the
// end (64 Ki ints = 256 KiB past base). On Ampere (A100) the SM raises a
// "Warp Out-of-range Address" fault, which the driver historically surfaces
// as XID 13 ("Graphics Engine Exception"). On some 595.x driver/GSP-RM
// revisions the same fault is classified as XID 43 instead (see
// xid43_trap.cu for background). Either outcome exercises the same XID→
// workload correlation path, so this reproducer validates the correlator
// regardless of which code the driver ultimately emits.
//
// Kept deliberately simple so it can be compiled and launched inside a
// short-lived k3s pod (nvidia/cuda:12.3.2-devel base image).
#include <cuda.h>
#include <stdio.h>
#include <unistd.h>

__global__ void oob(void)
{
	extern __shared__ int smem[];
	// Write ~256 KiB past the 256 B shared allocation.
	volatile int *p = smem + (64 * 1024);
	p[threadIdx.x] = 42;
}

int main(void)
{
	oob<<<1, 32, /* dynamic shmem bytes */ 256>>>();
	cudaError_t e = cudaDeviceSynchronize();
	fprintf(stderr, "sync: %s\n", cudaGetErrorString(e));
	sleep(2);
	return 0;
}
