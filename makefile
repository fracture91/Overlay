LIB=-Wall
CCPP=g++

all: overlay

overlay:
	$(CCPP) main.cpp -o overlay $(LIB)

clean: 
	rm -f overlay
