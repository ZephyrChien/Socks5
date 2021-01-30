s5: main.o socks5.o utils.o
	gcc -pthread main.o socks5.o utils.o -o s5
main.o: main.c
	gcc -c main.c -o main.o
socks5.o: socks5.c socks5.h
	gcc -c socks5.c -o socks5.o
utils.o: utils.c utils.h
	gcc -c utils.c -o utils.o
clean:
	rm *.o s5
