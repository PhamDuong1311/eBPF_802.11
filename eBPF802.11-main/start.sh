bpftool prog load hello.bpf.o /sys/fs/bpf/hello
bpftool net attach xdp pinned /sys/fs/bpf/hello dev wlx347de44144f6
./hello_usr
