# Cloudflare 优选IP自动抓取与更新

## 项目简介
本项目每3小时自动抓取 Cloudflare 优选IP，生成 `ip.txt`，并通过 GitHub Actions 自动化更新。

## 主要功能
- 定时抓取以下页面的 Cloudflare IP：
  - https://monitor.gacjie.cn/page/cloudflare/ipv4.html
  - https://ip.164746.xyz
  - https://cf.090227.xyz（JS动态渲染）
  - https://stock.hostmonit.com/CloudFlareYes（JS动态渲染）
- 自动去重，保证IP唯一
- 自动推送最新IP列表到仓库

## 项目结构
- `fetch_cloudflare_ips.py`：主抓取脚本，负责抓取、解析、去重、保存IP
- `ip.txt`：最新抓取的IP列表
- `.github/workflows/update-cloudflare-ip-list.yml`：GitHub Actions自动化配置
- `README.md`：项目说明文档
- `requirements.txt`：Python依赖包列表
- `config.yaml`：业务参数配置文件

## 依赖安装
本地运行需先安装依赖：
```bash
pip install -r requirements.txt
python -m playwright install
```
> 注意：Playwright 浏览器需单独安装，务必执行 `python -m playwright install`
> 
> 本项目异步抓取部分依赖 aiohttp，请确保 requirements.txt 中包含 aiohttp。

## 用法说明
直接运行脚本：
```bash
python fetch_cloudflare_ips.py
```

支持通过 config.yaml 配置数据源、输出、日志等级等，命令行参数可覆盖配置文件。

## 配置文件说明（config.yaml）
> 仅包含业务参数，依赖请见 requirements.txt
示例：
```yaml
sources:
  - https://monitor.gacjie.cn/page/cloudflare/ipv4.html
  - https://ip.164746.xyz
  - https://cf.090227.xyz
  - https://stock.hostmonit.com/CloudFlareYes
pattern: "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
output: "ip.txt"
timeout: 10
log: "fetch_cloudflare_ips.log"
max_workers: 4
log_level: "INFO"
js_retry: 3              # JS动态抓取最大重试次数
js_retry_interval: 2.0   # JS动态抓取重试间隔（秒）
```

优先级：命令行参数 > 配置文件 > 默认值

## 自动化流程（GitHub Actions）
- 每3小时自动运行脚本，抓取并更新IP列表
- 自动安装 Playwright 及浏览器，支持 JS 动态页面抓取
- 仅当`ip.txt`有变更时自动提交
- 支持手动触发和push触发

## 常见问题与解决办法
- 网络请求失败：请检查目标网站可用性或本地网络
- 依赖缺失：请确保已正确安装 requirements.txt 中所有依赖，并已执行 `python -m playwright install`
- 编码问题：脚本已指定utf-8编码，若仍有问题请反馈

## 优化与更新说明
- 2024-06：
  - 脚本结构重构，增加异常处理、去重、日志输出、类型注解
  - 支持 JS 动态页面抓取，集成 Playwright
  - 依赖管理规范化，依赖迁移至 requirements.txt
  - GitHub Actions 优化，自动安装 Playwright 及浏览器
  - README.md 完善
  - **2024-06-xx：**
    - 全量类型注解覆盖，PEP8格式化，关键函数补充注释
    - 细化网络、解析、文件写入等异常处理，提升健壮性
    - 代码风格与规范全面提升，便于维护和扩展

## 其他说明
- 如需扩展更多 JS 动态页面抓取，可参考 fetch_js_ips 函数实现

如有建议或问题欢迎反馈！
