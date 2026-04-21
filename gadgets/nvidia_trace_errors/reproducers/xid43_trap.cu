// Reproducer: XID 43 (GPU watchdog / unrecoverable software error) via PTX trap.
//
// NOTE on XID classification:
//   The CUDA `trap;` PTX instruction unconditionally faults the executing
//   warp. NVIDIA documentation historically classified this as XID 13
//   "Graphics Engine Exception", but on recent datacenter drivers (including
//   the 595.x series tested here on A100) the GSP-RM / resman subsystem
//   surfaces a `trap;`-induced fault as **XID 43** ("GPU stopped processing —
//   unrecoverable software error in kernel"), because the offending channel
//   is torn down as a software-initiated RC error rather than a compute
//   engine exception. Either classification exercises the same correlation
//   path (process-context kprobe, user stack, CUDA ring match), so the XID →
//   workload attribution machinery is validated regardless of which code the
//   driver emits. The observed xid_code on this host is **43**.
//
// Hardware-level XIDs (48/62/63/64/79) that require specific ECC-induced
// faults are out of scope on this shared A100 — see architecture.md §4.
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
