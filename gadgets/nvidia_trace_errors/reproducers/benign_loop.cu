// Benign CUDA workload: continuously calls cuStreamQuery in a loop so the
// gadget sees frequent libcuda activity from this container. Used in the
// multi-container cross-contamination test as the "innocent" pod.
#include <cuda.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
	cudaStream_t s;
	cudaStreamCreate(&s);
	for (int i = 0; i < 600; i++) {
		cudaStreamQuery(s);
		usleep(50000);
	}
	return 0;
}
