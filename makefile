all: test.c test2.c
	gcc -g -Wall -o test1 test1.c -lpcap

clean:
	rm -rf *.o test1

