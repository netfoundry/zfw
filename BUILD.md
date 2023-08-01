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
        make all
        sudo make install ARGS=<router|tunnel>
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
        make all
        sudo make install ARGS=<router|tunnel>
        ```     

    

