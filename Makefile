# IPK Projekt 1
# Autor: Radek Trebula

CC = gcc
CFLAGS = -Wall -Wextra -g
LOGIN = xtrebur00

all: ipk-L4-scan

ipk-L4-scan: main.o scanner.o tcp_scanner.o udp_scanner.o
	$(CC) $(CFLAGS) main.o scanner.o tcp_scanner.o udp_scanner.o -o ipk-L4-scan

main.o: main.c scanner.h
	$(CC) $(CFLAGS) -c main.c

scanner.o: scanner.c scanner.h
	$(CC) $(CFLAGS) -c scanner.c

tcp_scanner.o: tcp_scanner.c scanner.h
	$(CC) $(CFLAGS) -c tcp_scanner.c

udp_scanner.o: udp_scanner.c scanner.h
	$(CC) $(CFLAGS) -c udp_scanner.c

clean:
	rm -f ipk-L4-scan *.o $(LOGIN).zip

NixDevShellName:
	@echo c

zip:
	zip $(LOGIN).zip main.c scanner.c scanner.h Makefile README.md LICENSE CHANGELOG.md