CC = gcc
CFLAGS += -std=gnu11 -pedantic -Wall -Wextra \
	-Werror -Wno-missing-braces -Wno-missing-field-initializers \
	-Wno-unused-variable -Wno-unused-parameter -Wformat=2 -Wswitch-default \
	-Wno-unused-label -Wno-unused-function -Wcast-align -Wpointer-arith -Wbad-function-cast \
	-Wstrict-overflow=5 -Wstrict-prototypes -Winline -Wundef -Wnested-externs \
	-Wcast-qual -Wshadow -Wunreachable-code -Wfloat-equal \
	-Wstrict-aliasing=2 -Wredundant-decls -Wold-style-definition
LDFLAGS = -pthread
SOURCES = con_queue.c log.c device_handler.c event_thread.c config.c connection.c \
	data_channel.c snmp.c
EXEC_SOURCES = main.c scanner_cli.c
SOURCES += ber/ber.c ber/snmp.c
OBJECTS = $(patsubst %.c, build/%.o, $(SOURCES))
DEPS := $(OBJECTS:.o=.d)
EXECUTABLES = build/brother-scand build/brother-scan-cli
FIX_INCLUDE = fix_include
ETCDIR := /etc/brother-scand
BINDIR := /usr/bin
PRINTUSER := brother-scand
SYSTEMDPATH := /etc/systemd/system/$(PRINTUSER).service
SYSLOGPATH := /etc/rsyslog.d/$(PRINTUSER).conf

all: $(SOURCES) $(EXECUTABLES)

test:
	mkdir -p cmake
	(cd cmake; CC=clang CXX=clang++ cmake .. && make && CTEST_OUTPUT_ON_FAILURE=1 ctest)

iwyu: $(SOURCES)
	mkdir -p cmake
	(cd cmake; CC=clang CXX=clang++ cmake .. && make iwyu) 2>&1 | tee iwyu

fix_include: iwyu
	$(FIX_INCLUDE) --nosafe_headers < iwyu

-include $(DEPS)

ber/ber.c:
	git submodule init
	git submodule update

build/brother-scand: build/main.o $(OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)

build/brother-scan-cli: build/scanner_cli.o $(OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)

build/%.o: %.c
	@mkdir -p $(@D)
	$(CC) -c -MM -MF $(patsubst %.o,%.d,$@) $<
	$(CC) $(CFLAGS) -c -o $@ $<

install: all
	adduser --system --no-create-home $(PRINTUSER)
	cp $(EXECUTABLES) $(BINDIR)/
	mkdir -p $(ETCDIR)
	[ -e $(ETCDIR)/scanner.conf ] || cp out/brother.config $(ETCDIR)/scanner.conf
	for file in out/*.sh; do [ -e $(ETCDIR)/$$file ] || cp $$file $(ETCDIR)/; done
	chown -R $(PRINTUSER) $(ETCDIR)
	cp brother-scand.service $(SYSTEMDPATH)
	cp syslog.conf $(SYSLOGPATH)
	echo -e "Now edit $(ETCDIR)/scanner.conf. Then run:\n  systemctl restart rsyslog\n  systemctl enable $(PRINTUSER)"

install_ufw:
	cp brscand.ufw_profile /etc/ufw/applications.d/brscand
	ufw app update brscand
	ufw allow app brscand

uninstall:
	rm -ir $(ETCDIR) $(BINDIR)/brother-scan* $(SYSTEMDDPATH) $(SYSLOGPATH)
	deluser $(PRINTUSER)

.PHONY: clean test

clean:
	rm -f $(OBJECTS) $(DEPS) $(EXECUTABLES) build/*.o iwyu
