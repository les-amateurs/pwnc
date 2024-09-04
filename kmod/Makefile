obj-m += stop.o

PWD = $(CURDIR)
LINUX = $(HOME)/ctf/development/linux

all:
	make -C $(LINUX) M=$(PWD) modules

clean:
	make -C $(LINUX) M=$(PWD) clean