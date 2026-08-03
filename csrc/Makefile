# 无第三方依赖，只需 OpenSSL。macOS 用 brew 的 openssl@3；Linux 通常在系统路径。
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null || echo /usr)
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -I$(OPENSSL_PREFIX)/include
LDFLAGS ?= -L$(OPENSSL_PREFIX)/lib -lcrypto

# **每个门禁用到的二进制都必须在 all 里**。uacli / lookup_test 曾经不在，
# 结果 `make` 从不重建它们，门禁跑的是上一次手工编译的陈旧二进制——改了
# tlsfp.c 的行为，门禁却报旧行为，既能假绿也能假红。
all: ja4cli uacli lookup_test buildcli h2cli idcli cohcli kscli snitest kxcli hrrcli uastrcli libtlsfp.so

# **改了数据源就用 `make regen`，别手工 rm profiles.inc**。实测两次踩同一个坑：
# 手工删掉 inc 再 make，重建出来的仍是旧内容（wildcard 在 make 启动时求值，
# 而此时文件刚被删），于是 C 侧拿着陈旧的表跑、差分门禁报出并不存在的分歧，
# 而 make 全程不报错 —— 排查方向会被彻底带偏。
.PHONY: regen
regen:
	rm -f profiles.inc
	python3 gen_profiles.py > profiles.inc
	$(MAKE) all

# **依赖必须列全**：profiles.inc 还取决于段表产物，段表变了却不重建，C 侧就会
# 拿着旧表跑，而 make 不会报错 —— 差分门禁曾因此在还原变异后仍报 8 处不符，
# 实际源码早已恢复，只是 inc 没跟着重建。
profiles.inc: ../spec/profiles.json gen_profiles.py $(wildcard ../spec/segments/*.json)
	python3 gen_profiles.py > $@

tlsfp.o: tlsfp.c tlsfp.h profiles.inc
	$(CC) $(CFLAGS) -c tlsfp.c -o $@

# 共享库供 LuaJIT FFI 加载：所有导出函数都是内存进内存出、非阻塞的，
# 由 OpenResty 的 cosocket 在 Lua 侧驱动网络 I/O。
# **不链 libcrypto**：SHA-256 与 EVP 都走运行时 dlsym（见 tlsfp.c / tlsfp_kx.c 顶部）。
# 于是这个 .so 是纯 C 无外部依赖，可以按目标平台交叉编译后塞进部署包
# （与 vendor/protobuf/<TARGET>/pb.so 同一做法），也不会在 OpenResty 进程里
# 多塞一份 OpenSSL。链回去的话上面两条都会破。
libtlsfp.so: tlsfp.o tlsfp_kx.o
	$(CC) -shared -o $@ tlsfp.o tlsfp_kx.o -ldl

# **不 include openssl 头**：符号在运行时用 dlsym 解析，编译期不需要声明。
# 这样打包机的 OpenSSL 版本与 worker 里那份不一致也不会出问题。
tlsfp_kx.o: tlsfp_kx.c tlsfp_kx.h
	$(CC) $(CFLAGS) -c tlsfp_kx.c -o $@

uastrcli: tlsfp.o uastrcli.c
	$(CC) $(CFLAGS) -o $@ uastrcli.c tlsfp.o $(LDFLAGS)

hrrcli: tlsfp.o hrrcli.c
	$(CC) $(CFLAGS) -o $@ hrrcli.c tlsfp.o $(LDFLAGS)

kxcli: tlsfp_kx.o kxcli.c
	$(CC) $(CFLAGS) -o $@ kxcli.c tlsfp_kx.o $(LDFLAGS) -ldl

ja4cli: tlsfp.o ja4cli.c
	$(CC) $(CFLAGS) -o $@ ja4cli.c tlsfp.o $(LDFLAGS)

uacli: tlsfp.o uacli.c
	$(CC) $(CFLAGS) -o $@ uacli.c tlsfp.o $(LDFLAGS)

buildcli: tlsfp.o buildcli.c
	$(CC) $(CFLAGS) -o $@ buildcli.c tlsfp.o $(LDFLAGS)

h2cli: tlsfp.o h2cli.c
	$(CC) $(CFLAGS) -o $@ h2cli.c tlsfp.o $(LDFLAGS)

idcli: tlsfp.o idcli.c
	$(CC) $(CFLAGS) -o $@ idcli.c tlsfp.o $(LDFLAGS)

cohcli: tlsfp.o cohcli.c
	$(CC) $(CFLAGS) -o $@ cohcli.c tlsfp.o $(LDFLAGS)

# snitest 一直没有规则 —— 本机上它是早年手工编出来的，所以没人发现；
# 干净克隆里 test_build_parity 的"SNI 插入生效"那一项直接失败。
# 健壮性用的可执行：**必须带 ASan**。不带的话"没崩"只说明这次没踩到，
# 越界读写在只读表上常常无声无息 —— 而它跑在 nginx worker 里。
fuzzcli: tlsfp.c fuzzcli.c profiles.inc
	$(CC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
	  -DTLSFP_FUZZ_COUNTERS $(CFLAGS) -o $@ fuzzcli.c tlsfp.c $(LDFLAGS)

kscli: tlsfp.o kscli.c
	$(CC) $(CFLAGS) -o $@ kscli.c tlsfp.o $(LDFLAGS)

snitest: tlsfp.o snitest.c
	$(CC) $(CFLAGS) -o $@ snitest.c tlsfp.o $(LDFLAGS)

lookup_test: tlsfp.o lookup_test.c
	$(CC) $(CFLAGS) -o $@ lookup_test.c tlsfp.o $(LDFLAGS)

clean:
	rm -f *.o ja4cli uacli lookup_test buildcli h2cli idcli cohcli kscli snitest kxcli hrrcli uastrcli libtlsfp.so profiles.inc

.PHONY: all clean
