CC=gcc
CFLAGS=-I/opt/local/include
LD=gcc
LDFLAGS=-lcrypto -L/opt/local/lib

all: revoke_sign kconsole_sign

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%: %.o
	$(LD) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -rf *~ *.o *.elf *.bin *.s *_sign
