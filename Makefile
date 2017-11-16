CC=gcc
CFLAGS=-Wall -g -Werror
PROGS=nmpingd

all: $(PROGS)

debug: CFLAGS += -DDEBUG_NETMAP_USER
debug: $(PROGS)

nmpingd: nmpingd.o

clean:
	rm -f *.o $(PROGS)
