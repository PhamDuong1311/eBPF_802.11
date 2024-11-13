CC := gcc
INCLUDE := -lpcap
TARGET := adaptive_channel_hopping
TARGET_C := ${TARGET:=.c}

all: $(TARGET)
.PHONY: all
.PHONY: $(TARGET)

$(TARGET):
	$(CC) $(TARGET_C) -o $(TARGET) $(INCLUDE)
clean:
	rm -rf $(TARGET)
