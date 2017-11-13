CC=gcc
CFLAGS=-Wall -g -Werror
PROGS=netmapinetd

all: $(PROGS)

debug: CFLAGS += -DDEBUG_NETMAP_USER
debug: $(PROGS)

netmapinetd: netmapinetd.o

clean:
	rm -f *.o $(PROGS)
