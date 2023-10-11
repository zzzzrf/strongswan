CC = gcc
TARGET = bustest

INC = -I../../libstrongswan -I../../libcharon
LIBS =  -lpthread -lstrongswan -lcharon
LIBPATH = -L/usr/local/lib/ipsec

CLFAGS = $(INC) $(LIBPATH) $(LIBS) -O0 -g  -include /home/zrf/git/strongswan/build/config.h
DIRS = .
FILES = $(foreach dir, $(DIRS), $(wildcard $(dir)/*.c))
OBJ = $(patsubst %.c,%.o, $(FILES))

$(TARGET):$(OBJ)
	$(CC) -o $@ $^ $(CLFAGS) 

$(OBJ):%.o:%.c
	$(CC) -c $< -o $@ $(CLFAGS)

clean:
	rm -rf $(OBJ) $(TARGET) myswan.sock


