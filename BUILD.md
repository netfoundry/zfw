## Build from source
---
- OS/Platform: Ubuntu 22.04+ / amd64
    1. install libraries

        **Ubuntu 22.04 server / amd64** (kernel 5.15 or higher)

        ```bash
        sudo apt update
        sudo apt upgrade
        sudo reboot
        sudo apt install -y gcc clang libc6-dev-i386 libbpfcc-dev libbpf-dev libjson-c-dev make
        ```          


- OS/Platform: Ubuntu 22.04+ / arm64
    1. install libraries

        **Ubuntu 22.04 server / arm** (kernel 5.15 or higher)

        ```bash
        sudo apt update
        sudo apt upgrade
        sudo reboot
        sudo apt-get install -y gcc clang libbpfcc-dev libbpf-dev libjson-c-dev make
        ```          

- OS/Platform: RH 9.4 / x86_64
    1. install libraries

        ```bash
        sudo yum update
        sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms
        sudo dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
        sudo yum install -y clang bcc-devel libbpf-devel iproute-devel iproute-tc glibc-devel.i686 git json-c-devel
        ```              
    
- Build
    1. compile binaries
        ```bash      
        mkdir ~/repos
        cd repos
        git clone https://github.com/netfoundry/zfw.git 
        cd zfw/src
        make all
        sudo make install ARGS=<router|tunnel>
        ```
