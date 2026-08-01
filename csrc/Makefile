# 无第三方依赖，只需 OpenSSL。macOS 用 brew 的 openssl@3；Linux 通常在系统路径。
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null || echo /usr)
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -I$(OPENSSL_PREFIX)/include
LDFLAGS ?= -L$(OPENSSL_PREFIX)/lib -lcrypto

# **每个门禁用到的二进制都必须在 all 里**。uacli / lookup_test 曾经不在，
# 结果 `make` 从不重建它们，门禁跑的是上一次手工编译的陈旧二进制——改了
# tlsfp.c 的行为，门禁却报旧行为，既能假绿也能假红。
all: ja4cli uacli lookup_test libtlsfp.so

profiles.inc: ../spec/profiles.json gen_profiles.py
	python3 gen_profiles.py > $@

tlsfp.o: tlsfp.c tlsfp.h profiles.inc
	$(CC) $(CFLAGS) -c tlsfp.c -o $@

# 共享库供 LuaJIT FFI 加载：所有导出函数都是内存进内存出、非阻塞的，
# 由 OpenResty 的 cosocket 在 Lua 侧驱动网络 I/O。
libtlsfp.so: tlsfp.o
	$(CC) -shared -o $@ $< $(LDFLAGS)

ja4cli: tlsfp.o ja4cli.c
	$(CC) $(CFLAGS) -o $@ ja4cli.c tlsfp.o $(LDFLAGS)

uacli: tlsfp.o uacli.c
	$(CC) $(CFLAGS) -o $@ uacli.c tlsfp.o $(LDFLAGS)

lookup_test: tlsfp.o lookup_test.c
	$(CC) $(CFLAGS) -o $@ lookup_test.c tlsfp.o $(LDFLAGS)

clean:
	rm -f *.o ja4cli uacli lookup_test libtlsfp.so profiles.inc

.PHONY: all clean
