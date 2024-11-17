bpftool prog load hello.bpf.o /sys/fs/bpf/hello
bpftool net attach xdp pinned /sys/fs/bpf/hello dev wlx347de4440488
./hello_usr
