TARGET = hello
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}

all: $(TARGET) $(BPF_OBJ)
.PHONY: all
.PHONY: $(TARGET)

$(TARGET): $(BPF_OBJ) hello_usr
	rm -f /sys/fs/bpf/$(TARGET)
$(BPF_OBJ): %.o: %.c
	clang \
	    -g \
            -target bpf \
            -D __BPF_TRACING__ \
            -I/usr/include/$(shell uname -m)-linux-gnu \
            -Wall \
            -O2 -o $@ -c $<
hello_usr: hello_usr.c
	gcc -Wall -O2 -g $^ -o $@ -lbpf
clean:
	- rm -f /sys/fs/bpf/$(TARGET)
	- rm $(BPF_OBJ)
	- rm -rf $(USR)

