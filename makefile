all: Octopus.c
	gcc -g -Wall -o Octopus Octopus.c -lpcap

clean:
	rm -rf *.o Octopus
