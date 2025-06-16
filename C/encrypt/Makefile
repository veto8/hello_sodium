.PHONY: watch

windows:
	x86_64-w64-mingw32-gcc main.c -o main_64.exe
windows32:
	i686-w64-mingw32-gcc main.c -o main_32.exe
linux:
	gcc  main.c -o main_linux -lsodium
default: linux
