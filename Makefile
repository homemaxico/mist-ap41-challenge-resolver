CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c99
LDFLAGS = -lssl -lcrypto

TARGET = sha256_challenge
SRCS = sha256_challenge.c  eeprom.c challenge.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)

test:
	@./test_script.sh

clean:
	rm -f *.o  $(TARGET)
