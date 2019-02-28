all:
	gcc client.c -ansi -pedantic -Wall -std=c99 -o myclient
clean:
	-rm -fr myclient
