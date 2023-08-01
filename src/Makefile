SHELL=/bin/bash
IDIR = /usr/include/aarch64-linux-gnu/
CFLAGS=-I$(IDIR)
CC=clang
uname_m := $(shell uname -m)
all: zfw zfw_tc_ingress.o zfw_tc_ingress.o zfw_xdp_tun_ingress.o zfw_tc_outbound_track.o zfw_tunnwrapper
zfw: zfw.c
ifeq    ($(uname_m),aarch64)
	$(CC) -D BPF_MAX_ENTRIES=100000 -O1 -lbpf -o zfw  zfw.c $(CFLAGS)
else
	$(CC) -D BPF_MAX_ENTRIES=100000 -O1 -lbpf -o zfw  zfw.c
endif
zfw_tc_ingress.o: zfw_tc_ingress.c
ifeq    ($(uname_m),aarch64)
	$(CC) -D BPF_MAX_ENTRIES=100000 -g -O2 -Wall -Wextra -target bpf -c zfw_tc_ingress.c -o zfw_tc_ingress.o $(CFLAGS)
else
	$(CC) -D BPF_MAX_ENTRIES=100000 -g -O2 -Wall -Wextra -target bpf -c zfw_tc_ingress.c -o zfw_tc_ingress.o
endif
zfw_xdp_tun_ingress.o: zfw_xdp_tun_ingress.c
ifeq    ($(uname_m),aarch64)
	$(CC) -O2 -g -Wall -target bpf -c zfw_xdp_tun_ingress.c -o zfw_xdp_tun_ingress.o $(CFLAGS)
else
	$(CC) -O2 -g -Wall -target bpf -c zfw_xdp_tun_ingress.c -o zfw_xdp_tun_ingress.o
endif
zfw_tc_outbound_track.o: zfw_tc_outbound_track.c
ifeq    ($(uname_m),aarch64)
	$(CC) -g -O2 -Wall -Wextra -target bpf -c -o zfw_tc_outbound_track.o zfw_tc_outbound_track.c $(CFLAGS)
else
	$(CC) -g -O2 -Wall -Wextra -target bpf -c -o zfw_tc_outbound_track.o zfw_tc_outbound_track.c
endif
zfw_tunnwrapper: zfw_tunnel_wrapper.c
	$(CC) -o zfw_tunnwrapper zfw_tunnel_wrapper.c -l json-c
clean:
	rm -fr zfw zfw_tc_ingress.o zfw_tunnwrapper zfw_tc_ingress.o zfw_xdp_tun_ingress.o zfw_tc_outbound_track.o
install:
	./install.sh $(ARGS)
