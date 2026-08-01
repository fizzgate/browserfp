"""golden 文件的统一写入口 —— 默认合并，杜绝"只采子集把其余样本冲掉"。

**为什么要抽出来**：这个 bug 已经出现三次（browsers.py、h2collect.py、
goh2collect.py），最后一次把 h2_tls_client.json 的 71 条采集结果冲成 0 条。
每个采集器都支持"只采指定 profile"，一旦这么用又直接覆盖写，其余样本就静默消失
——覆盖矩阵与 h2 计数会随之变小，但**不会报任何错**，属于纯假绿。

事后审计发现 10 个采集器里有 6 个带这个风险，说明逐个修不可靠，必须收口到一处。
新采集器一律用 write_golden()，不要自己 json.dump 到 golden 目录。
"""

import json
import os


def write_golden(path, data, merge=True):
    """写 golden 文件。merge=True（默认）时先读回已有内容再更新。

    返回 (写入后的总条目数, 本次新增/更新的条目数)。
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    incoming = dict(data)
    if merge and os.path.exists(path):
        try:
            with open(path) as f:
                existing = json.load(f)
            if isinstance(existing, dict):
                existing.update(incoming)
                incoming = existing
        except (OSError, ValueError):
            pass          # 文件损坏或非 dict：按新数据重写，不静默丢弃本次结果
    with open(path, "w") as f:
        json.dump(incoming, f, indent=2, sort_keys=True)
        f.write("\n")
    return len(incoming), len(data)
