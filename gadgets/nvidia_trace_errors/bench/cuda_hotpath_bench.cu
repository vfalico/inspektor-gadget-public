// SPDX-License-Identifier: Apache-2.0
//
// bench/cuda_hotpath_bench.cu — hot-path overhead microbench for the
// nvidia_trace_errors XID→workload correlator.
//
// Exercises exactly the libcuda entry points the gadget uprobes:
//   - cuLaunchKernel
//   - cuStreamQuery
//   - cuMemcpyAsync -> cuMemcpyDtoHAsync_v2
//   - cuStreamSynchronize (once per run)
//
// A compute-bound kernel (work_iters FMAs/thread) is used so the
// measurement reflects realistic ML-style workloads rather than the
// cost of launching a no-op shader.  Prints a single JSON record to
// stdout for programmatic comparison by bench/overhead_stats.py.
//
// Build: nvcc -O2 -arch=sm_80 -o bench/cuda_hotpath_bench \\
//             bench/cuda_hotpath_bench.cu
#include <cuda_runtime.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>

__global__ void compute_kernel(float *p, int work_iters) {
    int tid = threadIdx.x;
    float acc = 0.0f;
    float x = p[tid];
    for (int i = 0; i < work_iters; ++i) {
        acc = acc * 1.0001f + x;
        x = x * 0.9999f + 1.0f;
    }
    if (tid == 0) p[0] = acc;
}

int main(int argc, char **argv) {
    const long N = (argc > 1) ? atol(argv[1]) : 5000;
    const int WORK = (argc > 2) ? atoi(argv[2]) : 2048;
    float *d; cudaMalloc(&d, 1024 * sizeof(float));
    cudaStream_t s; cudaStreamCreate(&s);
    float host = 0;
    for (int i = 0; i < 50; ++i) compute_kernel<<<1,1024,0,s>>>(d, WORK);
    cudaStreamSynchronize(s);
    auto t0 = std::chrono::steady_clock::now();
    for (long i = 0; i < N; ++i) {
        compute_kernel<<<1,1024,0,s>>>(d, WORK);
        cudaMemcpyAsync(&host, d, 4, cudaMemcpyDeviceToHost, s);
        cudaStreamQuery(s);
    }
    cudaStreamSynchronize(s);
    auto t1 = std::chrono::steady_clock::now();
    double ns_per_op = std::chrono::duration<double,std::nano>(t1 - t0).count() / N;
    printf("{\"n\":%ld,\"work_iters\":%d,\"ns_per_op\":%.1f,\"ops_per_sec\":%.0f,\"uprobed_calls_per_op\":4}\n",
           N, WORK, ns_per_op, 1e9 / ns_per_op);
    cudaStreamDestroy(s); cudaFree(d);
    return 0;
