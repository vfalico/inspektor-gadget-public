# cuda_observability

`cuda_observability` records factual CUDA Driver API returns and can optionally
emit bounded inference-activity timing candidates.

Raw `cuda_calls` telemetry is available in full by default. The explicit
capacity-safe mode may omit individual `cuCtxGetDevice` records while retaining
device attribution and complete aggregate accounting. Host API duration is not
GPU execution time, and the optional TTFT and decode-interval candidates are
not semantic token timings or request identities.

Check the full documentation on
https://inspektor-gadget.io/docs/latest/gadgets/cuda_observability.
