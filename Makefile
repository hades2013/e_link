
EXEC = MTC_e_link

OBJS = elink_public.o elink_dh.o elink_socket.o elink_packet.o elink_main.o cJSON.o arpping.o base64.o

CFLAGS	+= -DWEBS -DUEMF -DOS="LINUX" -DLINUX $(UMSW) $(DASW) $(SSLSW) $(IFMODSW)
CFLAGS  += -Wall -fno-strict-aliasing
CFLAGS	+= -I$(ROOTDIR)/lib/libnvram -I$(ROOTDIR)/$(LINUXDIR)/drivers/char -I$(ROOTDIR)/$(LINUXDIR)/include
CFLAGS  += -I$(ROOTDIR)/$(LINUXDIR)/drivers/flash 
OTHERS	= -DB_STATS -DB_FILL -DDEBUG
LDFLAGS	+= $(SSLLIB) $(IFMODLIB)
LDLIBS	+= -lnvram

CFLAGS += -I$(ROOTDIR)/user/MTC_private/common
LDLIBS	+= -L$(ROOTDIR)/user/MTC_private/common -luser_public  -lpthread 

CFLAGS += -I$(ROOTDIR)/user/openssl-0.9.8e/include
LDLIBS	+= -L$(ROOTDIR)/user/openssl-0.9.8e/ -lssl -lcrypto

CONF_H	= $(ROOTDIR)/$(LINUXDIR)/include/linux/autoconf.h
UCONF_H	= $(ROOTDIR)/config/autoconf.h

all: $(EXEC) 

$(EXEC): $(OBJS)
	$(CC) -o $@ $(OBJS) $(DEPEND_FILES) $(LDFLAGS) $(EXTRALIBS) $(LDLIBS) -lm

romfs:
	$(STRIP) $(EXEC)
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

