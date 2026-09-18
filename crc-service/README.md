# crc-service

一个可独立部署的循环冗余校验（CRC）核算微服务。上游系统把待传输或待落盘的数据交给它计算校验码，收端再用它验证数据是否被篡改或损坏。纯服务端组件：无登录、无账户、无前端。

- 语言：Go（仅标准库，零外部依赖）
- 部署：Docker 一键构建启动
- 计算模型：完全无状态，每次请求独立计算，并发安全

## 快速开始

### Docker（推荐）

```bash
docker build -t crc-service .
docker run --rm -p 8080:8080 crc-service
```

构建阶段会自动运行 `go vet` 和全部测试，测试不过则镜像构建失败。

### 本地运行

```bash
go test ./...        # 运行测试
go run ./cmd/crcd    # 监听 :8080，可用 PORT 环境变量覆盖
```

### 一眼核对公开测试向量

对 ASCII 字符串 `123456789`（hex `313233343536373839`）用 CRC-16/CCITT-FALSE 计算，权威目录公布的余数为 `0x29B1`：

```bash
curl -s -X POST localhost:8080/v1/checksum \
  -d '{"model":"CRC-16/CCITT-FALSE","data":"313233343536373839"}'
# {"check":"29B1","data_bytes":9,"model":"CRC-16/CCITT-FALSE","width":16}
```

`GET /v1/models` 返回的每一档都附带该测试向量的期望值，可直接对照。

## 参数档（models）

每一档完整描述一种 CRC 算法的全部约定：位宽 `width`、多项式 `poly`、寄存器初值 `init`、输入是否按位反转 `refin`、输出是否按位反转 `refout`、最终异或值 `xorout`。

| 名称 | width | poly | init | refin | refout | xorout | check("123456789") |
|---|---|---|---|---|---|---|---|
| CRC-8 | 8 | 0x07 | 0x00 | false | false | 0x00 | F4 |
| CRC-8/MAXIM | 8 | 0x31 | 0x00 | true | true | 0x00 | A1 |
| CRC-16/CCITT-FALSE | 16 | 0x1021 | 0xFFFF | false | false | 0x0000 | 29B1 |
| CRC-16/ARC | 16 | 0x8005 | 0x0000 | true | true | 0x0000 | BB3D |
| CRC-16/MODBUS | 16 | 0x8005 | 0xFFFF | true | true | 0x0000 | 4B37 |

除具名档外，调用方可在请求里用 `params` 直接给出显式参数临时构造一档。约束（违反即在计算前拒绝）：

- `width`：8–64 且为 8 的倍数（保证校验码字节对齐，可追加到报文后验证）
- `poly`：非零、不超过 `width` 位，且最低位（常数项）必须为 1。最低位为 0 的生成式含因子 x，存在无法检出的单比特错误，不属于合法 CRC 生成式；CRC 目录中的多项式最低位均为 1
- `init` / `xorout`：不超过 `width` 位

未登记的档名会返回 `unknown_model` 错误，服务绝不猜测或回退到默认档。

## 载荷编码格式（固定）

**载荷 `data` 一律为十六进制字符串**：大小写均可，允许可选的 `0x` 前缀，长度必须为偶数。空字符串是合法的空载荷（按 `init` 与 `xorout` 约定给出确定校验码，例如 CRC-16/CCITT-FALSE 得 `FFFF`）。任何不符合该格式的输入在计算前返回 `invalid_format` 错误。

## API

### POST /v1/checksum — 计算校验码

```json
{"model": "CRC-16/CCITT-FALSE", "data": "313233343536373839"}
```

或用显式参数（`model` 与 `params` 必须且只能给其一；`poly`/`init`/`xorout` 接受 JSON 数字或十六进制字符串）：

```json
{"params": {"width": 16, "poly": "0x1021", "init": "0xFFFF",
            "refin": false, "refout": false, "xorout": "0x0000"},
 "data": "313233343536373839"}
```

响应（`check` 为固定位宽的大写十六进制，宽度由 `width` 决定）：

```json
{"model": "CRC-16/CCITT-FALSE", "width": 16, "data_bytes": 9, "check": "29B1"}
```

### POST /v1/verify — 验证数据加校验码

```json
{"model": "CRC-16/CCITT-FALSE", "data": "313233343536373839", "check": "29B1"}
```

服务把校验码按该档的字节序约定追加到数据后（字节序由 `refin` 决定：`refin=true` 低位字节在前，`refin=false` 高位字节在前；`refin` 与 `refout` 不一致时校验码先做一次全宽按位反转再序列化），重新走一遍除法，余数等于该档约定的固定校验值（residue）时判为通过。这一序列化形式是 CRC 代数强制要求的：只有这样追加块才能消掉报文段的寄存器状态，使余数与报文内容无关——四种 `refin`/`refout` 组合由此在编码与校验两侧完全一致：

```json
{"model": "CRC-16/CCITT-FALSE", "width": 16, "valid": true,
 "residue": "0000", "expected_residue": "0000"}
```

数据或校验码中任意一个比特被翻转，`valid` 必为 `false`。

### GET /v1/models — 列出全部已登记参数档

返回每档的完整约定（width/poly/init/refin/refout/xorout）、公开测试向量 `123456789` 的期望余数、以及验证用的固定 residue。

### GET /healthz — 运行状态（供监控采集）

```json
{"status": "ok", "uptime_seconds": 123, "requests_total": 456, "requests_failed": 7}
```

## 错误响应

所有非法输入返回 HTTP 400（方法错误为 405）与结构化错误体，`error.type` 区分错误类型：

| type | 含义 |
|---|---|
| `unknown_model` | 档名未登记 |
| `invalid_format` | 载荷或校验码不是合法十六进制 |
| `invalid_params` | 显式参数越界（含偶数多项式）、model/params 同时给或都不给、校验码超出位宽 |
| `bad_request` | 请求体不是合法 JSON、HTTP 方法错误 |

```json
{"error": {"type": "unknown_model", "message": "unknown model: CRC-32"}}
```

## 实现要点

- **反转语义只定义一次**：`refin`（输入字节逐比特反转）与 `refout`（输出寄存器按全宽反转）只在 `internal/crc` 核心包中实现，编码与校验两侧、按位与查表两条路径共用同一处定义。校验码追加到报文时的序列化也只在一处（`CheckBytes`）实现：`refin` 决定字节序，`refin != refout` 时对校验码做一次全宽反转；四种组合不可能两侧不一致。
- **两条除法路径**：按位逐比特（参考实现）与按字节查表（256 项，注册时预计算）对同一输入给出完全相同的余数，测试对全部预置档和随机显式参数强制比对。
- **无状态**：每次请求独立计算，模型对象构建后不可变，唯一的可变量是监控计数器；并发测试与 `-race` 保证请求互不串扰。
- **验证原理**：`residue = CRC(data || checkBytes(check))` 是与报文内容无关的常数，注册时对空报文预计算一次，验证时比对即可。
- **单比特可检出性**：仅接受常数项为 1（奇数）的生成式，从参数层面保证合法参数档对任意单比特翻转的检出能力。

## 测试

```bash
go test ./...        # 单元 + HTTP 接口测试
go test -race ./...  # 竞态检测
```

覆盖：公开测试向量比对、编码后自校验、单比特翻转必失败、不同宽度档余数相异、输入/输出反转两侧一致、按位与查表两路同余、空载荷确定值、参数越界拒绝、未知档名拒绝、并发下多请求互不串扰。

## 项目结构

```
cmd/crcd/main.go            入口（PORT 环境变量，优雅退出）
internal/crc/               CRC 核心：参数、两条除法路径、模型、注册表
internal/server/            JSON/HTTP 接口层
Dockerfile                  多阶段构建（构建期跑测试，运行期非 root）
```
