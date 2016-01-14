OBJS =
OBJS += main.o

DEF = 
DEF += -O2
DEF += --std=c99 
DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 

LIBS =
LIBS += -lm

%.o: %.c
	gcc $(DEF) -c -o $@ $<

all: $(OBJS) 
	gcc -O3 -o pcap_merge $(OBJS)  $(LIBS)

clean:
	rm -f $(OBJS)
	rm -f pcap_merge

