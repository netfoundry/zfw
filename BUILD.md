## Build from source
---
- OS/Platform: Ubuntu 22.04 / amd64
    1. install libraries

        **Ubuntu 22.04 server / amd64** (kernel 5.15 or higher)

        ```bash
        sudo apt update
        sudo apt upgrade
        sudo reboot
        sudo apt install -y gcc clang libc6-dev-i386 libbpfcc-dev libbpf-dev libjson-c-dev
        ```          

    1. Compile:

        ```bash      
        mkdir ~/repos
        cd repos
        git clone https://github.com/r-caamano/zfw.git 
        cd zfw/src
        clang -g -O2 -Wall -Wextra -target bpf -c -o zfw_tc_ingress.o zfw_tc_ingress.c
        clang -g -O2 -Wall -Wextra -target bpf -c -o zfw_xdp_tun_ingress.o zfw_xdp_tun_ingress.c
        clang -g -O2 -Wall -Wextra -target bpf -c -o zfw_tc_outbound_track.o zfw_tc_outbound_track.c
        clang -O2 -lbpf -Wall -Wextra -o zfw zfw.c
        gcc -o zfw_tunnwrapper zfw_tunnel_wrapper.c -l json-c
    ```  

- OS/Platform: Ubuntu 22.04 / arm64
    1. install libraries

        **Ubuntu 22.04 server / arm** (kernel 5.15 or higher)

        ```bash
        sudo apt update
        sudo apt upgrade
        sudo reboot
        sudo apt-get install -y gcc clang libbpfcc-dev libbpf-dev libjson-c-dev
        ```          

    1. Compile:

        ```bash      
        mkdir ~/repos
        cd repos
        git clone https://github.com/r-caamano/zfw.git
        cd zfw/src
        clang -g -O2 -Wall -I /usr/include/aarch64-linux-gnu/ -Wextra -target bpf -c -o zfw_tc_ingress.o zfw_tc_ingress.c
        clang -g -O2 -Wall -I /usr/include/aarch64-linux-gnu/ -Wextra -target bpf -c -o zfw_xdp_tun_ingress.o zfw_xdp_tun_ingress.c
        clang -g -O2 -Wall -I /usr/include/aarch64-linux-gnu/ -Wextra -target bpf -c -o zfw_tc_outbound_track.o zfw_tc_outbound_track.c
        clang -O2 -lbpf -Wall -I /usr/include/aarch64-linux-gnu/ -Wextra -o zfw zfw.c
        gcc -o zfw_tunnwrapper zfw_tunnel_wrapper.c -l json-c
    ```     

    

