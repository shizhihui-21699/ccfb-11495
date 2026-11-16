# ioc-engine

STIX 2.1 IOC 匹配引擎:解析情报 bundle 中的 indicator,编译成高效匹配结构,多进程流式扫描大日志,输出带指标 ID 和置信度的命中记录。

## 使用

```bash
npm install && npm run build

# 扫描(输出 NDJSON 命中 + 跳过报告)
node dist/src/cli.js scan --intel bundle.json --log app.log --log other.log \
    --out hits.ndjson --workers 8

# 生成测试数据
node dist/src/cli.js gen-intel --out intel.json --count 30000 --seed 42
node dist/src/cli.js gen-logs --intel intel.json --out app.log --size-mb 1024 --hit-rate 0.002

npm test   # 单元测试
```

命中记录(NDJSON,每行一条):

```json
{"indicatorId":"indicator--…","indicatorName":"…","confidence":87,
 "matched":["domain:evil.com"],"file":"app.log","offset":33585049,"snippet":"…"}
```

跳过的 indicator(revoked / 过期 / 不支持的语法,含原因)写入 `<out>.skipped.json`。

## 支持的 pattern 子集

| 语法 | 说明 |
|---|---|
| `ipv4-addr:value = '1.2.3.4'` / `ipv6-addr:value = '…'` | 精确 IP |
| `ipv4-addr:value ISSUBSET '10.0.0.0/8'`(IPv6 同) | CIDR;`=` 后接带 `/` 的值也按 CIDR 处理 |
| `domain-name:value = 'evil.com'` | 域名,子域名可命中(见下) |
| `url:value = 'http://…'` | URL 精确匹配(大小写不敏感) |
| `file:hashes.'MD5'/'SHA-1'/'SHA-256'/'SHA-512' = '…'` | 文件哈希 |
| `AND` / `OR` / 括号 / 多 observation 组合 | 布尔组合,AND 优先级高于 OR |
| `x IN ('a','b',…)` | 展开为 OR |

**不支持的语法**(`MATCHES`、`LIKE`、`!=`、`NOT`、`>`/`<`、时间戳比较、`FOLLOWEDBY`、`WITHIN`、`REPEATS`、`resolves_to_refs[*]` 等引用路径、`network-traffic`/`process` 等未覆盖对象类型):**整条 indicator 跳过**,连同原因写进 skipped 报告。宁可漏报不可错报——部分求值会改变语义(比如 `AND` 里丢掉一半条件会放大误报)。`NOT` 和 `!=` 在行粒度匹配下语义危险(几乎恒真),明确拒绝。

## 关键设计决策

- **AND 的粒度是"同一行"**:行内所有原子都出现才命中。日志分析场景下行是天然事件边界;跨行关联(WITHIN/FOLLOWEDBY)属于流式关联引擎的范畴,不在此实现。
- **域名匹配**:Aho-Corasick 多模式自动机扫整行,命中后做边界校验——前一个字符不是 `[a-z0-9-]`(允许 `.`,所以 `sub.evil.com` 命中 `evil.com`,而 `notevil.com` 不命中),后一个字符不是 `[a-z0-9.-]`(所以 `evil.com.cn` 不命中 `evil.com`)。
- **URL 匹配**:同样走 AC 自动机,整体小写化(牺牲了 path 大小写敏感性,换来一次扫描同时匹配域名和 URL)。URL 后必须跟非 URL 字符,`http://a/x` 不会误中 `http://a/x2`。
- **CIDR**:二进制前缀 trie,IPv4(32 位)和 IPv6(128 位,BigInt)各一棵,查询即沿地址位走下 trie,收集路径上所有前缀。
- **精确 IP / 哈希**:哈希表。日志行用正则提取 IPv4/IPv6/hex-token 候选,严格解析校验后再查表(MAC 地址、时间戳这类形似 IPv6 的串会被解析器拒掉)。
- **评估优化**:atom → indicator 倒排索引。每行先求出命中的 atom 集合,只评估涉及这些 atom 的 indicator,而不是每行遍历几万条规则。
- **过期/撤销**:`revoked === true` 或 `valid_until < now` 的 indicator 在加载时剔除并计数。
- **置信度**:直接透传 indicator 的 `confidence` 字段(0–100),缺失为 `null`。

## 性能与内存

- 文件按字节区间切分给 worker_threads,每个 worker 流式按行处理(1 MiB 读缓冲),**内存占用与日志大小无关**:3 万条指标下整个进程树峰值约 2.3 GB(每个 worker 各自构建自动机,约 250 MB/进程),扫 256 MiB 和 1 GiB 日志内存持平。10 GB 日志可直接流式处理。
- 区间边界:worker 从非行首开始时丢弃第一个残行(除非前一字节是 `\n`),跨区间的行由起始位置所在的 worker 完整处理,保证每行恰好处理一次(测试:8 worker 与 1 worker 结果逐条一致)。
- 实测吞吐:单机约 **140–160 MiB/s**(3 万指标、8 worker)。瓶颈是每行的正则提取与 AC 扫描,与指标数的关系是亚线性的(AC 扫描复杂度只与文本长度和命中数有关)。

## 目录结构

```
src/
  patternParser.ts   STIX pattern 子集递归下降解析器
  compile.ts         pattern AST → 布尔表达式 + 原子(不支持的语法在此拒绝)
  stix.ts            bundle 加载,revoked/过期/非 stix pattern 过滤
  ipaddr.ts          IPv4/IPv6/CIDR 解析(BigInt)
  matchers/ahoCorasick.ts  多模式自动机(域名+URL)
  matchers/cidrTrie.ts     二进制前缀 trie(CIDR)
  engine.ts          匹配引擎:行 → atom 集合 → 倒排评估 indicator
  scanner.ts         字节区间流式按行扫描(内存恒定)
  worker.ts          worker 线程入口
  engineBuilder.ts   情报 → 引擎 的构建管线
  cli.ts             scan / gen-intel / gen-logs 命令
  gen/               测试情报与日志生成器
test/engine.test.ts  单元测试(node:test)
```
