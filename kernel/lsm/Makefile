CLANG ?= clang
LLC ?= llc

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Use vmlinux.h for BTF CO-RE relocations
INCLUDES := -I. -I/usr/include -I/usr/include/bpf

CFLAGS := -O2 -g -Wall -Wextra -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

all: obs.bpf.o loader

obs.bpf.o: obs.bpf.c vmlinux.h event.h
	$(CLANG) $(CFLAGS) -c $< -o $@

loader: loader.c event.h
	$(CC) -O2 -g -Wall -o $@ $< -lbpf -lelf -lz

clean:
	rm -f obs.bpf.o loader

.PHONY: all clean