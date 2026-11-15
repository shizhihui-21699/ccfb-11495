# IOC 匹配引擎（STIX 2.1）

用 TypeScript 在 Node 里实现的 IOC 扫描引擎，替代 `grep` 撞日志的做法。它从 STIX 2.1
bundle 里解析 `indicator` 的 `pattern`，把可精确求值的部分编译成索引，再对日志做流式、
多进程扫描，命中结果带指标 ID 与置信度。

```
$ node src/cli.ts gen-intel --out intel.json --seed 5 --count 60
$ node src/cli.ts gen-logs  --manifest intel.json.manifest.json --out logs --lines 1000000 --files 4
$ node src/cli.ts scan --intel intel.json --logs logs --output hits.jsonl
```

```json
{"file":"logs/access-0000.log","line":12,"offset":1544,
 "indicator_id":"indicator--103a66fa-…","indicator_name":"C2 198.18.0.3",
 "confidence":49,"labels":["malicious-activity"],
 "pattern":"[ipv4-addr:value = '198.18.0.3']","matched":"ipv4-addr:value = '198.18.0.3'",
 "text":"2026-06-10T00:28:44Z FW ALLOW src=10.146.126.136:53415 dst=198.18.0.3:8080 proto=tcp action=allow",
 "truncated":false}
```

## 快速开始

需要 Node ≥ 22.18（原生 TypeScript 执行）。

```bash
npm install          # 只装 typescript/@types/node（开发用）
npm test             # 166 个测试
npm run typecheck

# 生成情报 + 日志，然后扫描
node src/cli.ts gen-intel --out /tmp/intel.json --seed 5 --count 60
node src/cli.ts gen-logs  --manifest /tmp/intel.json.manifest.json --out /tmp/logs --lines 200000 --files 4
node src/cli.ts scan --intel /tmp/intel.json --logs /tmp/logs --output /tmp/hits.jsonl
node src/cli.ts validate --intel /tmp/intel.json --reasons
```

## 为什么不是 grep

| | grep | 本引擎 |
|---|---|---|
| 指标规模 ↑ | 线性变慢，需要多次遍历 | 一次遍历完成，成本与指标数基本无关 |
| 误报 | 子串匹配：`evil.com` 命中 `notevil.com` | 按标签边界做后缀匹配 |
| IP/CIDR | 文本匹配，`203.0.113.5` 命不中 `203.0.113.0/24` | 前缀树，最长前缀语义，IPv6 同样支持 |
| 组合条件 | 无法表达 | `AND` 要求同一条日志行内同时出现 |
| 生命周期 | 手工维护 | 自动剔除 `revoked` / 过期指标 |
| 内存 | 管道可用 | 单 worker + 200 MB 堆上限可扫 10 GB |

实测（14 核 Mac，SSD）：约 **60–160 MiB/s**（13 个 worker），单 worker 约 54 MiB/s；
10 GB 单文件在 `--max-old-space-size=200` 下完成扫描，峰值 RSS 约 500 MB（波动来自
worker 堆，不是输入大小驱动）。

## 支持的 pattern 语法

| 构造 | 例子 | 处理方式 |
|---|---|---|
| IPv4 / IPv6 字面量 | `[ipv4-addr:value = '1.2.3.4']` | 转为 /32、/128 前缀入树 |
| CIDR | `[ipv4-addr:value = '203.0.113.0/24']` | 前缀树，任意前缀长度，`/0` 也支持 |
| 域名 | `[domain-name:value = 'evil.com']` | 反向标签 Aho-Corasick；`a.evil.com` 命中，`notevil.com` 不命中 |
| URL | `[url:value = 'http://evil.com/x']` | 规范化后精确匹配（scheme/host 小写、默认端口、末尾斜杠） |
| 邮件地址 | `[email-addr:value = 'a@b.com']` | 精确匹配，同时把域名半边作为域名可观测对象 |
| 文件哈希 | `[file:hashes.'SHA-256' = '…']` | MD5 / SHA-1 / SHA-256 / SHA-512，长度校验，十六进制解码后比对 |
| `AND` | `[ipv4-addr:…] AND [domain-name:…]` | **要求同一条日志行内都出现** |
| `OR` | `… OR …` | 任一满足即可 |
| `IN` | `[ipv4-addr:value IN ('1.1.1.1','2.2.2.2')]` | 展开为 `OR` |
| `MATCHES` | `[domain-name:value MATCHES '^ads?\\.']` | 正则，逐候选值求值 |
| `LIKE` | `[domain-name:value LIKE '%.evil.com']` | `%`/`_` 转正则 |
| `ISSUBSET` | `[ipv4-addr:value ISSUBSET '10.0.0.0/8']` | 等价于 CIDR 包含判断 |

`AND` 的语义需要说明：STIX 规范里的 `AND` 是**观测级别**的组合，即「观察到 A 且观察到
B」。本引擎处理的是逐行日志，因此把 `AND` 定义为「同一行内同时出现」——这是单行输入
唯一能站得住脚的连接语义，也符合分析师写组合指标时的意图。需要跨行关联的
（`FOLLOWEDBY`、时间窗）**不支持**，见下节。

## 不支持的语法怎么处理

**原则：不猜测、不近似、整条拒绝并报出原因。** 部分降级（例如只保留 `AND` 的一侧）会
悄悄放宽指标，制造假命中，比明确跳过更糟——所以永远不做。

| 原因码 | 触发 | 为什么不支持 |
|---|---|---|
| `QUALIFIER_UNSUPPORTED:WITHIN` / `:REPEATS` / `:START` / `:STOP` / `:FOLLOWEDBY` | 观测限定符 | 需要跨行、跨时间的观测关联 |
| `OPERATOR_UNSUPPORTED:NEQ` | `!=` | 「没有抽取到等于 x 的可观测对象」对**每一条**不含该类型的日志都成立，会几乎全命中 |
| `OPERATOR_UNSUPPORTED:ORDERING` | `<` `>` `<=` `>=` | 对字符串型可观测对象没有检测意义 |
| `OPERATOR_UNSUPPORTED:NOT` / `:EXISTS` / `:ISSUPERSET` | 否定/存在/超集 | 需要观测级别的求值模型 |
| `OBSERVABLE_UNSUPPORTED` | `file:size`、`x509-certificate:*`、`process:*` 等 | 引擎不从文本里抽取这类对象 |
| `HASH_ALGORITHM_UNSUPPORTED` | `hashes.'SHA3-256'` | 未索引该算法 |
| `VALUE_INVALID` | 哈希长度不对、非法域名/URL/IP | 指标本身有问题 |
| `REGEX_INVALID` / `REGEX_TOO_LONG` / `LIKE_INVALID` | 正则编译失败或 >512 字符 | 拒绝而不是静默不匹配 |
| `PATTERN_SYNTAX` | 括号未闭合、字符串未闭合、缺少 `[` 等 | 语法错误 |

`iocscan validate` 会按原因聚合报告，方便判断覆盖率损失：

```
$ node src/cli.ts validate --intel intel.json --reasons
{
  "objects_in_bundle": 88,
  "indicators_live": 72,
  "programs_compiled": 65,
  "loader_skips": { "not_an_indicator": 6, "expired": 4, "revoked": 4, "not_yet_valid": 2 },
  "compile_rejections": { "OBSERVABLE_UNSUPPORTED": 2, "OPERATOR_UNSUPPORTED:NEQ": 1, … }
}
```

## 指标生命周期

加载时按扫描参考时钟（`--now`，默认当前时间）判断，**存活**需同时满足：

1. 未撤销（`revoked !== true`）；
2. `valid_from` 缺省或 ≤ now；
3. `valid_until` 缺省或 > now（右开区间：恰好等于 now 视为过期）。

补充规则：

- **同一 `id` 多版本**取 `modified`（缺则 `created`）最新的一条。较新的非撤销版本会覆盖
  较旧的撤销墓碑；反之较新的撤销墓碑不会被旧版本复活。
- **不按 `created` 过滤**：订阅源经常回填 `created`，只有 `valid_from` 是对的时钟。
- **时间戳无法解析**视为缺省，而不是「已过期」——宁可多扫也不要误杀。
- 撤销但仍在 bundle 里的对象会计入 `loader_skips.revoked`，不是静默消失。

## 架构

```
STIX bundle ──► bundle.ts ──► compile-set.ts ──► atom-index.ts       ┌─ worker ─┐
                (存活过滤)     (解析/编译/合并)     (构建索引)         │ engine   │
                                                                      ├─ worker ─┤
日志文件 ──────────────────────────────────────────► line-reader.ts ──►│ extract  │──► hits
                 (分片/动态调度)                       (流式/解压)     ├─ worker ─┤
                                                                      └──────────┘
```

索引结构与对应关系：

- **CIDR / IP** → `PrefixTrie`（IPv4 用 uint32，IPv6 用 4×uint32，扁平 typed array）。
  查询沿路径收集**所有**匹配前缀，天然给出最长前缀语义：/32 指标在 /8 指标范围内依然命中。
- **域名** → 反向标签的 Aho-Corasick 自动机。所有候选主机以小写反转后写入一块带 NUL
  分隔的缓冲区，一次遍历即可找出所有「作为标签边界后缀」的指标。这里的关键是只对
  **抽取出来的主机名**做匹配，URL 路径里的 `evil.com` 不会被当作主机。
- **URL / 邮件 / 哈希** → 字节键的开放寻址哈希表（`ByteMap`），直接对输入的字节区间
  查询，不为每个候选分配字符串。
- **组合** → `AND`/`OR` 表达式树，配原子 → 程序的倒排 postings。一行只求值「它的命中
  原子能触达的程序」，未命中任何原子的行代价只有一次抽取。

### 抽取器（`extract/extractor.ts`）

单次字节遍历，全程不生成字符串：

- IPv4：点分四段，拒绝前导零（`010.1.1.1` 不是 IP）、拒绝越界八位组；
- IPv6：可带 `[]`、`:port`、`/prefix`、`%zone`；
- 域名：多标签且 TLD 为字母，纯数字点分 token 不会被当作域名（`999.1.1.1`）；
- URL：识别行内任意位置的 `scheme://`（`url=http://…` 也可以），规范化后入表，
  authority 主机同时作为域名/IP 候选，查询串里的 IP 与哈希也会被扫到；
- 哈希：恰好 32/40/64/128 位十六进制，按长度判定算法。

### 多进程

Node 没有 POSIX `fork`，这里的「多进程」是 `worker_threads`：每个 worker 是独立 V8
isolate、独立堆、独立索引副本，跨核并行。索引不可序列化共享，所以主线程只把**纯 JSON
的 spec**（原子表 + 程序表达式 + 指标元数据）发给每个 worker，由 worker 各自重建——
构建索引是毫秒级的，换来的是无共享可变状态的干净并发。

调度是**动态**的：worker 完成一个文件就取下一下，大文件不会钉死单个 worker（文件按大小
降序入队，长文件先开始，短文件填满空档）。

故障策略：单个文件报错 → 标记失败、继续；worker 崩溃 → 重建并重排它手里的文件，超过
`maxWorkerRestarts`（默认 3）才整体中止。**不会静默丢数据**：未处理的文件在结束时登记为
失败，CLI 以退出码 3 结束。

## 流式与内存

`streaming/line-reader.ts` 用固定大小的可复用缓冲区，逐块切行：

- 支持无结尾换行、CRLF、跨块断行；
- `.gz` / `.zst` 透明解压（`node:zlib`）。
- 单行超过 `--max-line-bytes`（默认 8 MiB）→ 跳过并计数，**不**让它把内存撑爆。一个
  5 GB 的单行 JSON 会以 `overlong lines skipped` 报告，而不是 OOM。

命中结果默认流式写出（`--output` 或 stdout），worker 侧按 512 条一批回传，主线程不保留
全量命中集（`retainHits` 仅在测试/小规模下开启）。这正是 10 GB 扫描能维持有界内存的原因。

## 性能

```
=== index build ===
    1,000 indicators: json 1 ms,  compile+index 5 ms,  programs 1004,  atoms 816
   10,000 indicators: json 9 ms,  compile+index 20 ms, programs 10004, atoms 7396
   50,000 indicators: json 45 ms, compile+index 95 ms, programs 50004, atoms 32508

=== scan throughput ===
  951,106 lines/s, 94 MiB/s (single thread, 50k programs)

=== stage breakdown ===
  extraction is 79% of total line cost; index lookups are 21%
```

抽取占大头，因此扫描速度主要由日志行长度和 token 形态决定，而不是指标数量。50k 指标
对 100 万行的扫描仍是 60 MiB/s（13 worker）。

`npm run bench` 可复现，同时包含病态输入（128 KiB 单行、2000 个不同 IP 的单行）。

## 测试

```
npm test        # 166 个测试
npm run typecheck
```

测试覆盖：IP/前缀树边界、pattern 语法与每一个拒绝原因、AC 工程的跨主机边界、抽取器的
正负样本、bundle 生命周期（含「新版本撤销覆盖」「旧版本不复活墓碑」）、worker pool 的
并行一致性/失败处理/计数，以及端到端。

端到端测试用**注入真值**衡量，而不是拿引擎自己的输出来对：

1. `fixtures/intel.ts` 生成 STIX bundle + manifest，manifest 记录每个指标的 id、
   字面量、**期望的跳过/拒绝原因**；测试逐条比对，fixture 若悄悄丢掉某个 revoke 用例会失败。
2. `fixtures/logs.ts` 注入命中并同时注入**近似样本**（`evil.com` → `notevil.com`、
   IP 差一位、哈希差一个 nibble、AND 的两半拆到两行），每个近似样本都声明「不得命中哪个
   指标」。
3. 断言：真值 100% 召回、近似样本 0 命中、背景流量 0 误报。

地址空间在 fixture 里被刻意分离（背景流量避开指标使用的网段），否则「背景误报」测的
是 fixture 自己。

## 边界与限制

- **只有 ASCII / punycode 域名**。IDN 需要上游先转 punycode。
- **不处理 defanged 形式**（`hxxp://`、`evil[.]com`）。这是有意的：defang 规则因来源而
  异，猜错会制造假阴性；如需支持应当在上游做规范化。
- **哈希必须连续十六进制**，不带分隔符。
- **`AND` 是行内语义**，见上文；跨行/时间窗关联不支持。
- **行内不做重复上报**：一条日志行命中同一指标多次只报一次（原子级去重）；但日志里
  重复出现的同一行会各报一次——这正是取证需要的行为。
- **`MATCHES` / `LIKE` 成本随指标数增长**：精确字面量走索引，成本与指标数无关；但正则
  必须对每个候选值逐一求值。500 条域名正则会比无正则时慢约 6 倍（13 MiB 语料 0.29 s →
  1.75 s）。情报源里正则占比高时，应优先把它们改写成 `=` / CIDR。
- **worker 崩溃会导致文件级重复**：worker 死亡后其未完成的文件会被重排、从头重扫，
  因此该文件可能重复上报命中。这是刻意的 at-least-once 语义——告警场景下重复无害，
  漏报有害；无法容忍重复时请按 `(file, line, indicator_id)` 去重。
- 扫描是**无状态**的：不维护基线、不做频率异常检测。

## 配置与退出码

`--config <path>` 接受 JSON（CLI 参数优先）：

```json
{
  "intel": "feeds/daily.json.gz",
  "logs": ["/var/log/proxy", "/var/log/dns"],
  "workers": 8,
  "maxCaptureBytes": 1024,
  "maxHits": 100000,
  "format": "jsonl"
}
```

退出码：`0` 无命中、`1` 有命中、`2` 用法/配置错误、`3` 有输入处理失败。命中写 stdout
（JSONL，或 `--format csv`），诊断写 stderr，因此 `iocscan scan … | jq` 是干净的。

## 目录

```
src/
  cli.ts                 命令行入口
  config.ts              配置校验
  stix/pattern.ts        STIX pattern 词法/语法分析
  stix/compile.ts        语法树 → 可匹配表达式（含拒绝策略）
  stix/bundle.ts         bundle/NDJSON 加载、存活与去重
  stix/compile-set.ts    多指标合并、原子去重、postings、worker spec
  index/atom-index.ts    索引构建（trie / 域名 AC / 字节表 / 正则）
  match/aho-corasick.ts  稀疏 CSR Aho-Corasick
  match/domain.ts        反向标签域名匹配 + 主机缓冲区
  match/trie.ts          CIDR 前缀树（v4/v6）
  index-file/byte-map.ts 字节键开放寻址哈希表
  extract/extractor.ts   单遍字节级可观测对象抽取
  scan/line-matcher.ts   每行匹配（抽取 → 索引 → 原子位图）
  scan/engine.ts         程序求值、命中构造、计数
  scan/line-reader.ts    流式/解压行读取
  scan/worker.ts         worker 线程协议
  scan/pool.ts           动态调度、故障恢复
  fixtures/              确定性 PRNG、情报生成、日志生成（含真值）
tests/                   166 个测试
bench/                   基准
```
