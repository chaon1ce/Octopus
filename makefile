all: sock.c
	gcc -g -Wall -o sock sock.c -lpcap

clean:
	rm -rf *.o sock

