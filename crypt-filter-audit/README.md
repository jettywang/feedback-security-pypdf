# Crypt Filter 审计工作区

针对 pypdf 在普通流（StmF）、字符串（StrF）和嵌入文件流（EFF）上实际选择
哪个 Crypt Filter 的本地、可复现审计。结论见 `REPORT.md`。

## 文件

- `generate_samples.py` — 手工构建 V4/R4 128-bit 加密 PDF，完全控制
  `/CF`、`/StmF`、`/StrF`、`/EFF` 路由；覆盖 Identity、V2(RC4)、AESV2、
  压缩+加密组合、未知 CFM、`/None`、流级 `/Crypt`。
- `audit.py` — 探针记录 pypdf 为三个槽位实例化的 Crypt 类，并逐对象比对
  成功认证后的真实字节；产出 `results/audit.json` 与 `results/audit.txt`。
- `samples/` — 生成的 11 个受控 PDF（口令均为 `asdfzxcv`）。
- `results/` — 机器可读与文本审计结果。
- `REPORT.md` — 完整发现、字节证据、报错位置与不支持组合范围。

## 复现

```bash
.venv/bin/python crypt-filter-audit/generate_samples.py
.venv/bin/python crypt-filter-audit/audit.py
.venv/bin/python -m pytest tests/test_crypt_filter_selection.py -q -o addopts=""
```

回归测试 `tests/test_crypt_filter_selection.py` 自包含，不依赖本目录。
