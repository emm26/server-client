all:
	gcc client.c -ansi -std=c99 -pedantic -Wall -lpthread -o client
clean:
	-rm -fr client
