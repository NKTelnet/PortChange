obj-m += portchange.o

KDIR := /opt/SOURCES/linux-3.10.0-862.2.3.el7/

PWD := $(shell pwd)

all:
	$(RM) -rf $(PWD)/scripts
	ln -s $(KDIR)/scripts $(PWD)/scripts
	$(MAKE) -C $(KDIR) M=$(PWD) $(KDIR).config modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
