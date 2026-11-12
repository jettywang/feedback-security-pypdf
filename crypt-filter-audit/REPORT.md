# pypdf Crypt Filter 选择行为审计报告

- 被测版本：pypdf `7.0.1`（本仓库工作区）
- 标准依据：PDF 1.7 §7.6.2（加密字典 / Crypt Filters）、§7.4.10（流级 `/Crypt` 过滤器）、算法 1/3.1a
- 样本与脚本：`crypt-filter-audit/generate_samples.py`（受控样本生成）、`crypt-filter-audit/audit.py`（字节级审计）
- 机器可读结果：`crypt-filter-audit/results/audit.json`、`crypt-filter-audit/results/audit.txt`
- 回归测试：`tests/test_crypt_filter_selection.py`（10 项，全部通过）

所有样本均为手工构建的 V=4 / R=4 / 128-bit 标准安全处理器文档，使用同一用户口令
`asdfzxcv`、同一文件 ID，因此文件密钥可复现。每个文档都包含：
flate 压缩的页面内容流（StmF）、`/Info` 与文件规格里的字符串（StrF）、
一个未压缩嵌入文件流（obj 7）和一个 flate 压缩嵌入文件流（obj 8，EFF）。
样本之间只改 `/CF` + `/StmF /StrF /EFF` 的路由声明。

## 结论速览

1. pypdf 为三个槽位分别实例化了正确的 Crypt 实现，但**嵌入文件流（EFF）的解密器
   `ef_crypt` 被计算出来后从未被调用**——所有 `StreamObject`（含 `/EmbeddedFile`）
   都走 `stm_crypt`。这是“页面正常、附件乱码”的根因。
2. Identity、声明的默认过滤器（V2/AESV2）、压缩+加密组合在三个槽位**一致**时全部正确；
   一旦 EFF 与 StmF 不同，附件必然解密错误。
3. 未知 / 不支持的 CFM 在 `Encryption.read()` 阶段（口令校验**之前**）抛出
   `NotImplementedError`，消息能指出是哪个槽位和哪个方法，但**不含 `/Encrypt` 对象号**。
4. 流级 `/Crypt` 过滤器（带 `/Name`）属合法但不支持，解码时抛 `NotImplementedError`。

## 一、代码路径与实际选择的过滤器

### 1.1 方法名 → Crypt 类的映射

`pypdf/_encryption.py:1062` 的 `Encryption._get_crypt`：

| 方法名 (`/CFM`) | 返回的类 | 说明 |
|---|---|---|
| `/AESV2` | `CryptAES(aes128_key)` | AES-128 CBC，对象密钥含 `sAlT` |
| `/AESV3` | `CryptAES(aes256_key)` | AES-256 CBC，直接用文件密钥 |
| `/Identity` | `CryptIdentity()` | 恒等，原样返回字节 |
| `/V2` 及其它**任何**值 | `CryptRC4(rc4_key)` | 末尾兜底，静默回退 RC4 |

注意末尾的 RC4 兜底在读取路径上**不可达**：`Encryption.read()`
（`pypdf/_encryption.py:1291-1297`）用白名单
`("/Identity", "/V2", "/AESV2", "/AESV3")` 先做校验，白名单外的 CFM 直接抛
`NotImplementedError`。因此 `/Bogus` 不会真的落到 RC4 兜底，而是被提前拒绝。

### 1.2 三个槽位的实例化与实际使用

`Encryption._make_crypt_filter`（`pypdf/_encryption.py:989`）对每个被解密的间接对象
分别构造 `stm_crypt / str_crypt / ef_crypt`，封装进 `CryptFilter`
（`pypdf/_encryption.py:65`）。探针实测三者的类与声明完全一致，例如：

- `all-aes`（三槽均 `/AESV2`）→ `stm=CryptAES str=CryptAES ef=CryptAES`
- `stm-identity-str-rc4`（StmF=Identity, StrF=EFF=V2）→
  `stm=CryptIdentity str=CryptRC4 ef=CryptRC4`
- `eff-aes-mismatch`（StmF=StrF=V2, EFF=AESV2）→
  `stm=CryptRC4 str=CryptRC4 ef=CryptAES`

但 `CryptFilter.decrypt_object`（`pypdf/_encryption.py:99-113`）的分支是：

```python
if isinstance(obj, (ByteStringObject, TextStringObject)):
    data = self.str_crypt.decrypt(...)      # 字符串 -> str_crypt
elif isinstance(obj, StreamObject):
    obj._data = self.stm_crypt.decrypt(...)  # 所有流 -> stm_crypt（含嵌入文件！）
```

`ef_crypt` 在整个类里只在构造函数赋值，没有任何调用点。对
`eff-aes-mismatch` 样本的调用计数实测：

```
decrypt() 调用次数 -> {'stm': 3, 'str': 2, 'ef': 0}
```

嵌入文件流就是普通 `StreamObject`（`pypdf/generic/_files.py:234` 的
`_embedded_file` 经 `/EF /(U)F` 取到该流，`content` 属性在
`pypdf/generic/_files.py:275` 调 `get_data()`），读取时统一经过
`PdfReader._get_object` 的 `decrypt_object`（`pypdf/_reader.py:645`），
因此它永远拿 StmF 的解密器。

## 二、成功认证后各对象的实际字节

下表“声明”是 `/CF` 里通告的路由；“实际类”是探针记录的 pypdf 实例化结果；
对象结果是认证成功后 pypdf 暴露的字节与已知明文逐字节比对。完整数据见
`results/audit.json`。

### 2.1 三槽一致（基线，全部正确）

| 样本 | StmF/StrF/EFF | 实际三个类 | 页面流 obj4 | 字符串 obj10 | 嵌入文件 obj7 | 嵌入文件 obj8 |
|---|---|---|---|---|---|---|
| `all-rc4` | V2/V2/V2 | RC4/RC4/RC4 | 正确 | 正确 | 正确（256B 原文） | 正确（flate 解出 448B） |
| `all-aes` | AESV2/AESV2/AESV2 | AES/AES/AES | 正确 | 正确 | 正确（256B 原文） | 正确 |
| `all-identity` | Identity 全槽 | Identity×3 | 正确（明文） | 正确（明文） | 正确（256B 原文） | 正确 |

含义：当 EFF 恰好等于 StmF 时（pypdf 自身 `PdfWriter.encrypt` 写出的文件就是这种，
见下节），用 stm_crypt 解 EFF 流“碰巧正确”，所以常见加密 PDF 的附件不会出问题。

### 2.2 混合路由（StmF/StrF 独立，正常）

| 样本 | 声明 | 实际类 | 页面流 | 字符串 | 附件 |
|---|---|---|---|---|---|
| `stm-identity-str-rc4` | StmF=Identity, StrF=EFF=V2 | Identity/RC4/RC4 | 正确 | 正确 | **错误** |
| `stm-aes-str-rc4` | StmF=AESV2, StrF=EFF=V2 | AES/RC4/RC4 | 正确 | 正确 | **错误** |

StmF 与 StrF 是真正独立生效的：Identity 流被原样读出、RC4/AES 字符串各自正确解出，
证明普通流和字符串的路由没有问题。附件错误仅源于 EFF 被忽略。

### 2.3 EFF 与 StmF 不一致（复现“附件乱码”）

| 样本 | StmF | EFF（真实保护） | obj7 认证后字节 | 结果 |
|---|---|---|---|---|
| `eff-aes-mismatch` | V2(RC4) | AESV2 | 288B，前缀 `cd5cd46684fea0eb432ae0e6…` | RC4 误解 AES 密文，乱码 |
| `eff-identity-mismatch` | V2(RC4) | Identity(明文) | 256B，前缀 `55041848aec932cf03aa…` | 对明文再做 RC4，乱码 |
| `stm-identity-str-rc4` | Identity | V2(RC4) | 256B，前缀 `55041848aec932cf03aa…` | 该 RC4 密文被当明文，乱码 |
| `stm-aes-str-rc4` | AESV2 | V2(RC4) | 97B，前缀 `5cb672fe49814f35527b2034…` | AES 误解 RC4 密文，长度也变 |

flate 压缩附件 obj8 在所有不一致样本中均报
`zlib.error: Error -3 while decompressing data: incorrect header check`，
经公开 API `reader.attachments` 读取时表现为空 bytes（`b""`）或垃圾字节，
与用户反馈的“附件解出来是乱码”完全吻合。压缩与加密的先后顺序本身正确
（先 flate 再加密，读取时先解密再 inflate），失败纯粹是过滤器选错。

## 三、坏配置的报错（对象位置与原因）

未知/不支持的 CFM 在 reader 构造期的 `Encryption.read()` 内被拒绝，
调用栈为 `PdfReader.__init__ → _handle_encryption
（pypdf/_reader.py:206）→ Encryption.read`，**早于** `verify()` 口令校验
（`pypdf/_reader.py:211`）。因此即便口令正确也不会进入解密阶段，属于快速失败。

| 样本 | 触发槽位 | 异常类型 | 确切消息 | 抛出位置 |
|---|---|---|---|---|
| `unknown-stmf` | StmF=/Bogus | `NotImplementedError` | `StmF Method /Bogus NOT supported!` | `_encryption.py:1293` |
| `none-strf` | StrF=/None | `NotImplementedError` | `StrF Method /None NOT supported!` | `_encryption.py:1295` |
| `unknown-eff` | EFF=/Bogus | `NotImplementedError` | `EFF Method /Bogus NOT supported!` | `_encryption.py:1297` |

配套的结构性校验（同样在 `Encryption.read()`）能给出更具体的入口名：

- `/CF` 不是字典 → `PdfReadError: /CF entry of the encryption dictionary is not a dictionary`
- `/StmF` 等引用的具名过滤器缺失 →
  `PdfReadError: Crypt filter /StdCF is missing from /CF or not a dictionary`
  （`_get_crypt_filter`，`_encryption.py:894`）
- `/StmF` 条目类型错误 → `PdfReadError: /StmF entry of the encryption dictionary is not a name`
- 缺 `/CFM` 时默认成 `/None`，随即命中上面的 `… Method /None NOT supported!`

**位置信息的局限**：消息能明确指出是哪个槽位（StmF/StrF/EFF）和哪个 CFM 方法，
但不带 `/Encrypt` 间接对象的对象号/世代号，也不带出错 crypt filter 字典的对象号。
这是因为校验发生在只持有加密字典、尚无具体被解密对象上下文的阶段；对象级定位要到
后续 `decrypt_object(obj, idnum, generation)` 才有，而那里已不再做 CFM 校验。

## 四、当前不支持的合法组合（范围说明）

1. **EFF 与 StmF 不同的嵌入文件加密（核心缺口）**
   PDF 1.7 §7.6.2 允许 `/EFF` 单独指定嵌入文件流的过滤器，且允许流通过
   `/Crypt` 过滤器自行指定。pypdf 能解析并保存 `/EFF`、也构造了 `ef_crypt`，
   但解密与加密都不使用它：
   - 解密：`CryptFilter.decrypt_object` 对所有流用 `stm_crypt`（`_encryption.py:104`）。
   - 加密/写出：`Encryption.write_entry` 直接注释 `# ignore EFF`
     （`_encryption.py:1213-1214`），`PdfWriter.encrypt` 无法生成 EFF 不同的文档。
   实测 R6/AES-256（`r6-user-password.pdf`）三槽均为 `/AESV3`、V1/V2（RC4）
   三槽默认 `/V2`，这些“三槽相同”的合法文档正常；只有 EFF 分叉的合法文档受影响。

2. **流级 `/Crypt` 过滤器（PDF 1.7 §7.4.10）**
   流的 `/Filter` 数组里出现 `/Crypt` 且 `/DecodeParms` 带 `/Name` 或 `/Type` 时，
   `pypdf/filters.py:1025-1029` 抛
   `NotImplementedError: /Crypt filter with /Name or /Type not supported yet`。
   无参数的 `/Crypt`（等价 Identity）被静默跳过。审计样本
   `samples/stream-crypt-specifier.pdf` 复现了该路径。

3. **非 Standard 安全处理器与子过滤器**
   `/Filter != /Standard` → `NotImplementedError: only Standard PDF encryption handler is available`
   （`_encryption.py:1243`）；出现 `/SubFilter` →
   `NotImplementedError: /SubFilter NOT supported`（`_encryption.py:1247`）。
   因此公钥安全（PubSec）等合法处理器不在支持范围。

4. **CFM 方法白名单之外的算法**
   读取仅接受 `/Identity /V2 /AESV2 /AESV3`。历史上的 `/V1`（40-bit RC4 具名过滤器）、
   任何厂商自定义 CFM 都会在 `Encryption.read()` 抛 `NotImplementedError`。
   加密版本号 `V` 仅支持 1–5，其它值抛
   `NotImplementedError: Encryption V=… NOT supported`（`_encryption.py:1255`）。

## 五、复现方式

```bash
# 生成 10 个受控样本 + 1 个流级 /Crypt 样本
.venv/bin/python crypt-filter-audit/generate_samples.py
# 字节级审计，产出 results/audit.json 与 results/audit.txt
.venv/bin/python crypt-filter-audit/audit.py
# 回归测试（自包含，不依赖审计目录）
.venv/bin/python -m pytest tests/test_crypt_filter_selection.py -q -o addopts=""
```

修复建议（不在本次改动范围内，仅作指引）：在 `CryptFilter.decrypt_object` 中识别
嵌入文件流（其字典 `/Type == /EmbeddedFile`，或经由文件规格 `/EF` 引用）并改用
`self.ef_crypt`；对称地在 `encrypt_object` 与 `write_entry` 落地 `/EFF`，
即可让 EFF 分叉的合法文档正确往返。
