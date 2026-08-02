"""模拟器采集的有效性依据仍然成立 —— 判定它"等于真机"的那条论证不能烂掉。

本项目唯一的移动端实采来自 iOS 模拟器。模拟器与真机是不是同一个网络栈，不能
靠推断（"它跑的是 iOS WebKit 构建，应该一样吧"），当初的判定靠的是**交叉验证**：

  h2   采到的 akamai 指纹与 curl_cffi / tls_client / wreq **三家独立库**
       记录的 Safari iOS 17 逐字节一致
  TLS  JA4 与 `curl_cffi:safari172_ios` 完全相同

三家各自采自真机的数据同时对上，模拟器假象解释不了。**但这是一条会过期的论证**：
库更新一版、golden 被改一次，依据就可能不成立了，而 golden 里那份 iOS 数据仍会
被当成"实采背书"用下去 —— 头序、h2、注册表三处都靠它。

所以把当初那条论证固化成门禁，而不是写进提交说明就算了。它**不重新采集**
（重采要人盯着模拟器），验的是"入库的那份仍然与三家独立库一致"。

跑：python -m spec.test_simulator
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oracle.simcollect import verify                          # noqa: E402


def main():
    bad = verify()
    for b in bad:
        print(f"  ✗ {b}")
    print("\n" + ("模拟器采集的有效性依据仍成立" if not bad
                  else f"{len(bad)} 处问题"))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
