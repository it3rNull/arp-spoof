LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o send_arp.o arphdr.o ethhdr.o mac.o ip.o checksum.o kb.o pch.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
