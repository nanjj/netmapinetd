CC=gcc
CFLAGS=-Wall -g -Werror
PROGS=nmpingd nmcat

all: $(PROGS)

debug: CFLAGS += -DDEBUG_NETMAP_USER
debug: $(PROGS)

nmpingd: nmpingd.o
nmcat: nmcat.o

clean:
	rm -f *.o $(PROGS)
