
CFLAGS = -std=c99 -g -pedantic -Wall -Wextra

SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin


LIBINCLUDE = -I/usr/include \
             -I/usr/local/include

LDPATH =     -L/usr/local/lib/ \
             -L/usr/lib/x86_64-linux-gnu

LIBS =       coap-3 tss2-esys tss2-sys tss2-mu tss2-tctildr tss2-rc

# TCTI module to use (default is 'mssim')
TCTI_MODULE=tss2-tcti-mssim
ifdef with-tcti
	TCTI_MODULE=tss2-tcti-$(with-tcti)
endif
LIBS += $(TCTI_MODULE)


LDFLAGS_DYNAMIC = $(addprefix -l, $(LIBS))

LDFLAGS_STATIC = $(addprefix -l:lib, $(addsuffix .a, $(LIBS)))

SOURCES = $(shell find $(SRCDIR) -name '*.c')

INCLUDE = -I$(INCDIR)

OBJECTS =   $(addsuffix .o, $(OBJDIR)/fobnail-attester)
OBJECTS +=  $(addsuffix .o, $(OBJDIR)/tpm2-crypto)

TARGETS = $(addprefix $(BINDIR)/, fobnail-attester)


.PHONY: all clean

## --- targets ------------------------------------------------------------ ##

all: LDFLAGS = $(LDFLAGS_DYNAMIC)
all: $(TARGETS)

$(BINDIR)/fobnail-attester: $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@


## --- objects ------------------------------------------------------------ ##

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c

clean:
	$(RM) bin/*
	$(RM) obj/*.*
