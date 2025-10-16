# IPFind - Linux 版本

## 项目概述

IPFind 是一个跨平台的网络连接IP威胁情报分析工具，专门为Linux系统优化。该工具能够自动提取系统网络连接中的外部IP地址，并通过VirusTotal API进行批量威胁情报查询。

## 系统要求

### 支持的操作系统
- **Ubuntu** 18.04+
- **Debian** 10+
- **CentOS** 7+
- **RHEL** 8+
- **Fedora** 30+
- **Arch Linux**
- 其他基于systemd的Linux发行版

### 软件要求
- **Python** 3.8+
- **网络工具**: `ss` 或 `netstat`
- **依赖包**: 详见 requirements.txt

## 快速开始

### 1. 自动安装（推荐）

```bash
# 进入IPFind目录
cd scripts/IPFind

# 运行安装脚本
chmod +x install_linux.sh
./install_linux.sh
```

### 2. 手动安装

```bash
# 安装系统依赖
# Ubuntu/Debian:
sudo apt update
sudo apt install python3-pip python3-venv net-tools

# CentOS/RHEL:
sudo yum install python3-pip python3-venv net-tools

# 安装Python依赖
pip3 install -r requirements.txt

# 设置执行权限
chmod +x ipfind_cli.py
```

### 3. 设置API密钥

首次使用需要设置VirusTotal API密钥：

```bash
# 获取免费API密钥：https://www.virustotal.com/gui/join-us

# 设置API密钥
python3 ipfind_cli.py --set-api-key YOUR_API_KEY

# 或使用安装后的命令
ipfind --set-api-key YOUR_API_KEY
```

## 使用方法

### 图形界面版本

```bash
python3 ipfind_app.py
```

### 命令行版本

#### 自动分析网络连接
```bash
ipfind --auto
```

#### 从文件分析IP地址
```bash
ipfind --input ips.txt
```

#### 手动分析指定IP
```bash
ipfind --ips "8.8.8.8,1.1.1.1,192.168.1.1"
```

#### 显示详细输出
```bash
ipfind --auto --verbose
```

#### 检查API密钥状态
```bash
ipfind --check-api-key
```

### 完整命令行帮助

```bash
ipfind --help
```

## 功能特性

### 🔍 核心功能
- **跨平台IP提取**: 自动适配Linux系统的网络工具（ss/netstat）
- **智能IP筛选**: 自动过滤本地IP地址，专注于外部连接分析
- **威胁情报查询**: 集成VirusTotal API v3，获取全面的威胁分析数据
- **多种分析模式**: 支持自动提取、文件输入、手动输入三种模式

### 🛡️ 安全分析
- **威胁等级评估**: 根据恶意检测数量自动分级
- **多维度分析**: 包含恶意检测数、可疑检测数、无害检测数等
- **地理位置信息**: 显示IP地址的地理位置和网络运营商信息
- **历史分析数据**: 包含最后分析时间和记录创建时间

### 📊 输出格式
- **CSV格式**: 便于导入Excel或其他分析工具
- **彩色终端输出**: 直观显示威胁等级
- **详细日志**: 完整的操作记录和错误跟踪

## 文件说明

### 核心文件
- `ipfind_app.py` - 图形界面主程序
- `ipfind_cli.py` - 命令行版本主程序
- `ip_extractor.py` - 跨平台IP提取模块
- `ip_analysis.py` - VirusTotal API查询模块
- `config_manager.py` - 配置管理模块
- `logger.py` - 日志管理模块

### 生成文件
- `config.json` - 配置文件（包含API密钥）
- `ips.txt` - 提取的IP地址列表
- `output.csv` - 分析结果CSV文件
- `logs/ipfind.log` - 日志文件

## 技术细节

### 网络连接提取
Linux版本使用 `ss` 命令（优先）或 `netstat` 命令来获取网络连接信息：

```bash
# 使用 ss 命令（推荐）
ss -tun

# 使用 netstat 命令（备选）
netstat -tun
```

### API限制处理
- **免费账户**: 4次/分钟，500次/天
- **自动延迟**: 每个请求间隔15秒，避免触发限制
- **错误处理**: 自动处理429（额度不足）等错误

### 威胁等级定义

| 等级 | 图标 | 恶意检测数 | 说明 |
|------|------|------------|------|
| 安全 | 🟢 | 0 | 未发现恶意行为 |
| 低危 | 🟠 | 1-2 | 少量恶意检测 |
| 中危 | 🟡 | 3-9 | 中等恶意检测 |
| 高危 | 🔴 | ≥10 | 大量恶意检测 |

## 故障排除

### 常见问题

#### 1. 权限问题
```bash
# 确保有权限执行网络命令
sudo ipfind --auto

# 或将用户添加到相关组
sudo usermod -a -G network $USER
```

#### 2. 网络工具不可用
```bash
# 安装网络工具
sudo apt install net-tools  # Ubuntu/Debian
sudo yum install net-tools  # CentOS/RHEL
```

#### 3. Python依赖问题
```bash
# 重新安装依赖
pip3 install --upgrade -r requirements.txt

# 或使用虚拟环境
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

#### 4. API密钥无效
```bash
# 重新设置API密钥
ipfind --set-api-key NEW_API_KEY

# 检查密钥状态
ipfind --check-api-key
```

### 日志查看
```bash
# 查看详细日志
tail -f logs/ipfind.log

# 或使用详细模式运行
ipfind --auto --verbose
```

## 高级用法

### 定时任务分析
```bash
# 每天定时分析网络连接
0 2 * * * /usr/local/bin/ipfind --auto --output /var/log/ipfind/daily_$(date +\%Y\%m\%d).csv
```

### 集成到监控系统
```bash
# 只分析高危IP并发送警报
ipfind --auto | grep "高危" | mail -s "发现高危IP" admin@example.com
```

### 批量处理IP列表
```bash
# 从多个文件分析
for file in ip_lists/*.txt; do
    ipfind --input "$file" --output "results/$(basename "$file" .txt).csv"
done
```

## 开发说明

### 代码结构
```
IPFind/
├── ipfind_app.py          # 图形界面主程序
├── ipfind_cli.py          # 命令行主程序
├── ip_extractor.py        # 跨平台IP提取
├── ip_analysis.py         # 威胁分析模块
├── config_manager.py      # 配置管理
├── logger.py              # 日志管理
├── requirements.txt       # Python依赖
├── install_linux.sh       # Linux安装脚本
└── README_LINUX.md        # Linux专用文档
```

### 扩展开发
- 支持添加其他威胁情报源
- 可扩展为实时监控工具
- 支持导出报告和图表

## 许可证

本项目采用 MIT 许可证。

## 免责声明

本工具仅用于教育和安全研究目的。使用者应遵守当地法律法规，不得用于非法用途。作者不对使用本工具造成的任何后果负责。

---

**注意**: 使用 VirusTotal API 需要遵守其服务条款和使用限制。请合理使用API资源，避免触发限制。