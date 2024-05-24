LDLIBS += -lpcap

all: csa_attack

csa_attack: csa_attack.o

csa_attack.o: csa_attack.c

clean:
	rm -f csa_attack.o csa_attack