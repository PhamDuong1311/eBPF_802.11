bpftool net detach xdp dev wlx347de44144f6
rm -f /sys/fs/bpf/hello
rm -f hello.bpf.o hello_usr
rm -f /sys/fs/bpf/xdp_map_count1
