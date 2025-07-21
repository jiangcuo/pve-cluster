DEPENDENCIES=libcpg libcmap libcorosync_common libquorum libqb glib-2.0 fuse sqlite3 librrd

# Support cross-compilation by using environment variables
CC ?= gcc
AR ?= ar
PKG_CONFIG ?= pkg-config

# If DEB_HOST_GNU_TYPE is set (cross-compilation), use cross-compiler
ifdef DEB_HOST_GNU_TYPE
    CC = $(DEB_HOST_GNU_TYPE)-gcc
    AR = $(DEB_HOST_GNU_TYPE)-ar
    # Use standard pkg-config but with target architecture paths
    PKG_CONFIG = env PKG_CONFIG_LIBDIR=/usr/lib/$(DEB_HOST_GNU_TYPE)/pkgconfig:/usr/share/pkgconfig pkg-config
    # Add target architecture library path for cross-compilation
    LDFLAGS += -L/usr/lib/$(DEB_HOST_GNU_TYPE)
endif

CFLAGS += -std=gnu99
CFLAGS += -Wall -Werror -Wno-unknown-pragmas -Wno-strict-aliasing
#CFLAGS += -Wpedantic
CFLAGS += -g -O2
CFLAGS += -I.
CFLAGS += $(shell $(PKG_CONFIG) --cflags $(DEPENDENCIES))

LDFLAGS += -Wl,-z,relro $(shell $(PKG_CONFIG) --libs $(DEPENDENCIES))

ARFLAGS = crs

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $< -MMD -MT $@ -MF $@.d

all: pmxcfs create_pmxcfs_db logtest check_memdb

libpmxcfs.a: logger.o loop.o server.o status.o confdb.o quorum.o dcdb.o dfsm.o
libpmxcfs.a: cfs-plug.o cfs-plug-memdb.o cfs-plug-link.o cfs-plug-func.o
libpmxcfs.a: cfs-utils.o memdb.o database.o
libpmxcfs.a:
	$(AR) $(ARFLAGS) $@ $^

pmxcfs: pmxcfs.o libpmxcfs.a
	$(CC) -o $@ $^ $(LDFLAGS)


create_pmxcfs_db: create_pmxcfs_db.o libpmxcfs.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

logtest: logtest.o libpmxcfs.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

logtest2: logtest2.o libpmxcfs.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

check_memdb: check_memdb.o libpmxcfs.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(shell $(PKG_CONFIG) --libs check)

pmxcfs.8:

-include /usr/share/pve-doc-generator/pve-doc-generator.mk

.PHONY: install
install: pmxcfs create_pmxcfs_db pmxcfs.8
	install -D -m 0755 pmxcfs $(DESTDIR)/usr/bin/pmxcfs
	install -D -m 0755 create_pmxcfs_db $(DESTDIR)/usr/bin/create_pmxcfs_db
	install -D pmxcfs.8 $(DESTDIR)/usr/share/man/man8/pmxcfs.8

.PHONY: tidy format
tidy: format
format:
	git ls-files ':/src/pmxcfs/*.[ch]' | xargs -n2 -P0 -- clang-format -i

.PHONY: check
check: check_memdb
	./check_memdb

.PHONY: clean
clean:
	rm -f *.o *.o.d *.a pmxcfs create_pmxcfs_db check_memdb logtest pmxcfs.8

-include *.o.d
