FROM nvidia/cuda:12.3.2-devel-ubuntu22.04
COPY *.cu /src/
RUN nvcc -arch=sm_80 /src/xid13_trap.cu -o /usr/local/bin/xid13 && \
    nvcc -arch=sm_80 /src/xid31_uaf.cu -o /usr/local/bin/xid31 && \
    nvcc -arch=sm_80 /src/benign_loop.cu -o /usr/local/bin/benign
CMD ["/bin/bash"]
