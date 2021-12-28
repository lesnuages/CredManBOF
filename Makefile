BOFNAME := credman
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC=x86_64-w64-mingw32-clang

all:
	$(CC_x64) -o $(BOFNAME).x64.o -Os -c CredMan.c 
	$(CC_x86) -o $(BOFNAME).x86.o -Os -c CredMan.c 

test:
	$(CC_x64) CredMan.c -o $(BOFNAME).x64.exe
	$(CC_x86) CredMan.c -o $(BOFNAME).x86.exe

clean:
	rm $(BOFNAME).*.exe
	rm *.o