# Add _DEFAULT_SOURCE macro to avoid compiler errors for some GNU expressions
CFLAGS = -std=c99 -g -pedantic -Wall -Wextra -D_DEFAULT_SOURCE

SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin
QCBORDIR = 3rdparty/QCBOR

LIBINCLUDE = -I/usr/include \
             -I/usr/local/include \
             -I./$(QCBORDIR)/inc

LDPATH =     -L/usr/local/lib/ \
             -L/usr/lib/x86_64-linux-gnu \
             -L./$(QCBORDIR)

LIBS =       coap-3 tss2-esys tss2-sys tss2-mu tss2-tctildr tss2-rc crypto curl
STATIC_LIBS = qcbor

# TCTI module to use (default is 'mssim')
TCTI_MODULE=tss2-tcti-mssim
ifdef with-tcti
	TCTI_MODULE=tss2-tcti-$(with-tcti)
endif
LIBS += $(TCTI_MODULE)


LDFLAGS_DYNAMIC = $(addprefix -l, $(LIBS))

LDFLAGS_STATIC = $(addprefix -l, $(STATIC_LIBS))

SOURCES = $(shell find $(SRCDIR) -name '*.c')

INCLUDE = -I$(INCDIR)

OBJECTS =   $(addsuffix .o, $(OBJDIR)/fobnail-attester)
OBJECTS +=  $(addsuffix .o, $(OBJDIR)/tpm2-crypto $(OBJDIR)/meta_data $(OBJDIR)/dmi_decode)

TARGETS = $(addprefix $(BINDIR)/, fobnail-attester)

EXTERNALS = $(addprefix $(QCBORDIR)/, libqcbor.a)

.PHONY: all clean

## --- targets ------------------------------------------------------------ ##

all: LDFLAGS = $(LDFLAGS_DYNAMIC) $(LDFLAGS_STATIC)
all: $(EXTERNALS) $(TARGETS)

$(BINDIR)/fobnail-attester: $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@

## --- objects ------------------------------------------------------------ ##

$(QCBORDIR)/libqcbor.a:
	$(MAKE) -C $(@D) $(@F) CMD_LINE="-DUSEFULBUF_DISABLE_ALL_FLOAT"

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c

clean:
	$(MAKE) -C $(QCBORDIR) clean
	$(RM) bin/*
	$(RM) obj/*.*
