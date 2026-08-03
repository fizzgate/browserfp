// kybercli —— Kyber768（NIST 第三轮）的判据。
//
// TLS 里的 X25519Kyber768Draft00（组 0x6399）用的**不是** ML-KEM-768：它是
// Kyber 第三轮那版，与最终标准在 FO 变换与矩阵 A 的转置上都不同，OpenSSL 只有
// 最终版。所以这一族得自己实现，而实现要有外部判据。
//
// 判据取 CIRCL 的 kem/kyber/kyber768（它的文档明确写着 "as submitted to round 3
// of the NIST PQC competition"，与 kem/mlkem 是两个包）。
//
// 全部走确定性接口：同一个种子必须产出同一份密钥/密文，C 侧才有得比。
//
//	kybercli kat <n>            → 每行 seedhex\tekhex\tdkhex\tencseedhex\tcthex\tsshex
//	kybercli decap <dk> <ct>    → sshex
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: kybercli kat <n> | kybercli decap <dkhex> <cthex>")
		os.Exit(2)
	}
	sch := kyber768.Scheme()

	switch os.Args[1] {
	case "kat":
		n, _ := strconv.Atoi(os.Args[2])
		for i := 0; i < n; i++ {
			// 种子取一个确定的模式，跑多少次都一样 —— 门禁要可复现
			seed := make([]byte, sch.SeedSize())
			for j := range seed {
				seed[j] = byte(i*31 + j*7 + 1)
			}
			pk, sk := sch.DeriveKeyPair(seed)
			ek, _ := pk.MarshalBinary()
			dk, _ := sk.MarshalBinary()

			es := make([]byte, sch.EncapsulationSeedSize())
			for j := range es {
				es[j] = byte(i*17 + j*3 + 5)
			}
			ct, ss, err := sch.EncapsulateDeterministically(pk, es)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n",
				hex.EncodeToString(seed), hex.EncodeToString(ek),
				hex.EncodeToString(dk), hex.EncodeToString(es),
				hex.EncodeToString(ct), hex.EncodeToString(ss))
		}
	case "encap":
		// 拿给定的 ek（可能来自别的实现）做一次真·第三轮 Kyber 封装
		ek, _ := hex.DecodeString(os.Args[2])
		pk, err := sch.UnmarshalBinaryPublicKey(ek)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ct, ss, err := sch.Encapsulate(pk)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("%s\t%s\n", hex.EncodeToString(ct), hex.EncodeToString(ss))

	case "decap":
		dk, _ := hex.DecodeString(os.Args[2])
		ct, _ := hex.DecodeString(os.Args[3])
		sk, err := sch.UnmarshalBinaryPrivateKey(dk)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ss, err := sch.Decapsulate(sk, ct)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(ss))
	default:
		os.Exit(2)
	}
}
