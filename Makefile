all:
	gcc client.c -ansi -std=c99 -pedantic -Wall -lpthread -o myclient
clean:
	-rm -fr myclient
