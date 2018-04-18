
CC = g++
CFLAGS = -c -std=c++11
TARGET = out

$(TARGET): main.o utils.o cipher_padding.o cipher_des.o
	$(CC) main.o utils.o cipher_padding.o cipher_des.o -o $(TARGET)

main.o: main.cpp utils.h cipher_des.h cipher_padding.h
	$(CC) $(CFLAGS) main.cpp

cipher_des.o: cipher_des.cpp cipher_des.h cipher_params.h
	$(CC) $(CFLAGS) cipher_des.cpp

cipher_padding.o: cipher_padding.cpp cipher_padding.h
	$(CC) $(CFLAGS) cipher_padding.cpp

utils.o: utils.cpp utils.h
	$(CC) $(CFLAGS) utils.cpp

clean: 
	rm *.o $(TARGET)
