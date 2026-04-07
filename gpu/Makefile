NVCC = nvcc
NVCCFLAGS = -O3

all: qsb_search

qsb_search: qsb_search.cu GPUMath.h GPUHash.h qsb_params.h
	$(NVCC) $(NVCCFLAGS) -o $@ qsb_search.cu -lcrypto -lm
	chmod +x launch_multi_gpu.sh

clean:
	rm -f qsb_search

.PHONY: all clean
