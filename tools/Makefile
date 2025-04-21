CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c99

TARGET = console_login
SRCS = chroot_wrapper.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)

#test: $(TARGET)
#	@./test_script.sh

clean:
	rm -f *.o  $(TARGET)
