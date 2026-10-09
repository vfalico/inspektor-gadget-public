# cuda_observability

`cuda_observability` records factual CUDA Driver API returns and can optionally
emit bounded inference-activity timing candidates.

Raw `cuda_calls` telemetry is always available. Host API duration is not GPU
execution time, and the optional TTFT and decode-interval candidates are not
semantic token timings or request identities.

Check the full documentation on
https://inspektor-gadget.io/docs/latest/gadgets/cuda_observability.
