# 多功能安全MCP工具

> 面向云主机、服务器和虚拟机环境的自动威胁检测、安全基线合规和矿机分析一体化安全运维助手。支持实时发现、日志、API接口和可视化仪表盘。

## 基本介绍

**Multi-Function Security MCP**（多功能安全MCP）是基于Python开发的一款安全综合检测、基线审计和自动化取证工具。通过集成核心检测任务、实时日志、API及Web仪表盘，协助安全运维人员第一时间发现安全隐患、矿机活动和合规风险。

## 视频演示
[![点击观看 Demo 视频](https://i0.hdslb.com/bfs/archive/4ac3afcdfadf211aa9fc90906527a3a1b4f326b2.jpg)](https://www.bilibili.com/video/BV1MZSzBDEZS)

**主要特性：**
- **五大安全工具任务：**
  - `log_analysis` 日志分析：检测异常登录、密码失败、crontab和权限变更等系统/应用日志异常。
  - `security_check` 基础安全检查：快速扫描高危开放端口和疑似恶意进程。
  - `traceability_analysis` 关联溯源分析：自动关联各类IOC与检测结果，推断攻击链和异常联系。
  - `baseline_check` 安全基线检测：检测系统是否符合企业基线要求（文件权限、服务白名单/黑名单、sysctl配置等）。
  - `miner_analysis` 矿机检测分析：识别CPU/GPU挖矿进程、钱包和矿池域名、异常持久化行为。
- **API接口与仪表盘**：通过HTTP接口获取实时发现、任务状态、工具列表、完整日志（`mcp.log`）。
- **实时事件推送**：支持SSE流（Server-Sent Events）接收JSON格式发现/风控升级事件。
- **Web仪表盘**：可视化总览、最新发现、任务进度和实时监控。
- **进程与网络检测安全**：进程、端口、文件均通过`psutil`、安全子进程管理，减少误杀及权限问题。
- **认证保护**：大部分API与页面采用Basic Auth访问控制。
- **任务去重与冷却机制**：任务调用具备冷却周期与并发保护，防止重复扫描及频繁触发。
- **可选组件灵活降级**：`fastmcp`、`whois`、`aiohttp`等依赖不存在时自动禁用相关功能。
- **详细日志记录**：所有工具调用、任务执行、异常处理都记录到文件和控制台，方便取证和排查。

---

## 系统架构简介

- **任务管理器**：调度与去重定时任务、自动执行安全检测，维护发现与决策引擎联动。
- **决策引擎**：依据发现数量、严重等级自动判定是否需要升级处置（如阻断/隔离/修复）。
- **API接口层**：aiohttp框架实现，RESTful接口获取发现、任务、工具清单、日志及实时事件流（SSE）。
- **MCP工具服务器**：若安装`fastmcp`，自动暴露工具API接口用于自动化编排与集成。

---

## 安装方法

**依赖环境：**
- Python 3.8及以上
- [psutil](https://pypi.org/project/psutil/)
- [aiohttp](https://pypi.org/project/aiohttp/) （推荐，提供Web与API）
- [python-whois](https://pypi.org/project/python-whois/) （可选，加强IOC分析能力）
- [PyYAML](https://pypi.org/project/PyYAML/) （加载自定义IOC方便）

```bash
pip install psutil aiohttp python-whois pyyaml
```
或
```bash
pip install -r requirement
```

> _未安装可选组件时，相关功能自动禁用，不影响主流程运行。_

---

## 快速启动

```bash
python multi_func_security_mcp.py --auth-user admin --auth-pass securepassword --log-level INFO
```

- Web仪表盘与API端口默认8080，访问 `http://localhost:8080`
- MCP工具服务（如安装fastmcp）端口为8000
- mcp配置json
```bash
{
  "mcpServers": {
    "miner-detector-mcp": {
      "command": "/home/uweic/miniconda3/bin/python3",
      "args": [
        "/home/uweic/shoot/tool_mcp/multi_func_security_mcp.py"
      ]
    }
  }
}
```

**环境参数建议**
- 支持命令行指定API认证与日志级别，无需环境变量。

---

## 主要功能、接口及用法

### 核心安全工具清单（`/api/tools_manifest`）

| 工具名               | 功能和适用场景                                         | 安全 | 需认证 | 调用举例 |
|----------------------|--------------------------------------------------------|------|--------|----------|
| log_analysis         | 系统/应用日志异常分析                                  | ✅   | ❌     | —        |
| security_check       | 快速端口/进程安全扫描                                  | ✅   | ❌     | —        |
| traceability_analysis| IOC与发现自动溯源分析                                  | ✅   | ❌     | —        |
| baseline_check       | 基线配置合规审查（需要敏感权限）                       | ✅   | ✅     | —        |
| miner_analysis       | 矿机行为识别与持久化检测                               | ✅   | ❌     | —        |

### 主要API接口

- `/api/findings` — 获取全部检测发现及指标（JSON）。
- `/api/tasks` — 当前/历史任务执行状态。
- `/api/log` — 全部日志文件（审计与异常分析）。
- `/api/tools_manifest` — 工具列表及参数格式（无需认证）。
- `/events` — 实时SSE事件流（发现/安全风控升级）。
- `/` — Web仪表盘公开最新发现与总体运行状态。

除清单接口外，均需要Basic Auth认证。

### 认证方式

| 参数           | 说明                    | 默认值          |
|----------------|-------------------------|-----------------|
| auth-user      | API和Web访问用户名       | `admin`         |
| auth-pass      | API和Web访问密码         | `securepassword`|

---

## 安全与健壮性

- **权限敏感**：具备root检测和权限回退机制，读取敏感文件失败亦不影响主流程。
- **安全子进程**：命令行调用均有限时、可控，避免注入和僵尸进程问题。
- **去重与冷却机制**：防止任务风暴和误杀。
- **认证保护**：敏感API和页面均需认证，证书可自定义。
- **鲁棒性与兼容性**：所有可选功能在依赖缺失时完美降级，异常自动记录。
- **线程/协程安全**：核心任务队列采用锁和asyncio队列，提高并发安全性。
- **可取证日志**：详细日志到文件，配合API支持自动审计与风控追溯。

---

## 个性化扩展

- **自定义IOC**：可通过自定义YAML文件扩展矿机、恶意进程、域名、脚本等指标，启动时用`--ioc-file`参数指定。
- **参数配置**：所有任务执行周期、冷却时间及检查阈值均可代码层或命令行灵活调整。
- **基线内容定制**：可按实际运维要求调整`SECURITY_BASELINE`字典内容。

---

## 局限说明

- **表层分析为主**：工具只做非破坏性检测与建议，未自动执行隔离或修改系统内容。
- **平台兼容性有限**：部分功能需Linux环境、具备root权限。
- **安全运维辅助**：建议结合其他安全产品及人工运维。

---

## 开源声明

本项目为安全研究用途开源，MIT协议，风险自担，请务必结合实际环境调优和测试。

---

## 参与与反馈

欢迎提issue、PR！源码及后续更新见 [honysyang/mcp_tools](https://github.com/honysyang/mcp_tools) 。

---

## 相关参考

- [psutil官方文档](https://psutil.readthedocs.io/)
- [aiohttp官方文档](https://docs.aiohttp.org/)
- [OWASP Security Baseline](https://owasp.org/)
- [NIST Secure Baseline](https://csrc.nist.gov/)
