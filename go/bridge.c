/* cgo 桥：把 C 实现直接编进 Go 包，这样 `go build` 一步到位，
 * 不需要用户先 make 出 libbrowserfp.so 再配 LD_LIBRARY_PATH。
 *
 * 用 #include 而不是把 .c 列进包目录：cgo 只编译**包目录内**的 .c 文件，
 * 而实现在 ../csrc（与 lua 绑定共享同一份，不复制）。 */
#include "browserfp.c"
#include "browserfp_kx.c"
