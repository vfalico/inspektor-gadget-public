// Reproducer: XID 13 (Graphics Engine Exception) via PTX trap.
// trap; is a PTX instruction that unconditionally faults the running thread.
// The driver surfaces the fault as XID 13 in the offending context.
#include <cuda.h>
#include <stdio.h>
#include <unistd.h>

__global__ void tripwire(void)
{
	asm volatile("trap;");
}

int main(void)
{
	tripwire<<<1, 1>>>();
	cudaError_t e = cudaDeviceSynchronize();
	fprintf(stderr, "sync: %s\n", cudaGetErrorString(e));
	sleep(2);
	return 0;
}
