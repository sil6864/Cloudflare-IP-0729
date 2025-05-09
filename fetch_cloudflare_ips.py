# -*- coding: utf-8 -*-
import os
import re
import logging
import argparse
import time
from typing import List, Set, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter, Retry
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, Page
import asyncio
import aiohttp

# 新增：读取yaml配置
try:
    import yaml
except ImportError:
    yaml = None
    print("未检测到 PyYAML，请先运行 pip install pyyaml")

# ---------------- 配置区 ----------------
# 所有配置均从 config.yaml 读取，缺失项直接报错

def load_config(config_path: str = 'config.yaml') -> Dict[str, Any]:
    """
    读取并校验 config.yaml 配置文件。
    :param config_path: 配置文件路径
    :return: 配置字典
    :raises: RuntimeError, FileNotFoundError, ValueError, KeyError
    """
    if not yaml:
        raise RuntimeError('未检测到 PyYAML，请先运行 pip install pyyaml')
    if not os.path.exists(config_path):
        raise FileNotFoundError('未找到 config.yaml 配置文件，请先创建')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            if not isinstance(config, dict):
                raise ValueError('config.yaml 格式错误，需为字典结构')
            # 必须字段校验
            required = ['sources', 'pattern', 'output', 'timeout', 'log', 'max_workers', 'log_level', 'js_retry', 'js_retry_interval']
            for k in required:
                if k not in config:
                    raise KeyError(f'config.yaml 缺少必需字段: {k}')
            return config
    except Exception as e:
        raise RuntimeError(f"读取配置文件失败: {e}")

# ---------------- 日志配置 ----------------
def setup_logging(log_file: str, log_level: str = 'INFO') -> None:
    """
    配置日志输出到文件和控制台。
    :param log_file: 日志文件名
    :param log_level: 日志等级（如INFO、DEBUG等）
    :return: None
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(message)s',
        handlers=[
            logging.FileHandler(log_file, mode='w', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

# ---------------- 工具函数 ----------------
def extract_ips(text: str, pattern: str) -> Set[str]:
    """
    从文本中提取所有IP地址。
    :param text: 输入文本
    :param pattern: IP正则表达式
    :return: IP集合
    """
    return set(re.findall(pattern, text))

def save_ips(ip_set: Set[str], filename: str) -> None:
    """
    保存IP集合到文件。
    :param ip_set: IP集合
    :param filename: 输出文件名
    :return: None
    """
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            for ip in sorted(ip_set):
                file.write(ip + '\n')
        logging.info(f"共保存 {len(ip_set)} 个唯一IP到 {filename}")
    except Exception as e:
        logging.error(f"写入文件失败: {filename}，错误: {e}")

# ---------------- requests重试配置 ----------------
def get_retry_session(timeout: int) -> requests.Session:
    """
    获取带重试机制的requests.Session。
    :param timeout: 超时时间
    :return: 配置好的Session
    """
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.request = lambda *args, **kwargs: requests.Session.request(session, *args, timeout=timeout, **kwargs)
    return session

# ---------------- 智能抓取 ----------------
def fetch_ip_auto(
    url: str,
    pattern: str,
    timeout: int,
    session: requests.Session,
    page: Optional[Page] = None,
    js_retry: int = 3,
    js_retry_interval: float = 2.0
) -> Set[str]:
    """
    自动判断页面类型并抓取IP，优先静态，失败后用JS动态。
    :param url: 目标URL
    :param pattern: IP正则
    :param timeout: 超时时间
    :param session: requests.Session
    :param page: Playwright Page对象
    :param js_retry: JS动态抓取最大重试次数
    :param js_retry_interval: JS动态抓取重试间隔（秒）
    :return: IP集合
    """
    logging.info(f"[AUTO] 正在抓取: {url}")
    # 先尝试静态抓取
    try:
        response = session.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        elements = soup.find_all('tr') if soup.find_all('tr') else soup.find_all('li')
        ip_set: Set[str] = set()
        for element in elements:
            ip_set |= extract_ips(element.get_text(), pattern)
        if ip_set:
            logging.info(f"[AUTO] 静态抓取成功: {url}，共{len(ip_set)}个IP")
            return ip_set
        else:
            logging.info(f"[AUTO] 静态抓取无IP，尝试JS动态: {url}")
    except requests.RequestException as e:
        logging.warning(f"[AUTO] 静态抓取失败: {url}，网络错误: {e}，尝试JS动态")
    except Exception as e:
        logging.warning(f"[AUTO] 静态抓取失败: {url}，解析错误: {e}，尝试JS动态")
    # 动态抓取（带重试）
    if page is not None:
        for attempt in range(1, js_retry + 1):
            try:
                page.goto(url, timeout=30000)
                page.wait_for_timeout(3000)
                ip_set = extract_ips(page.content(), pattern)
                if ip_set:
                    logging.info(f"[AUTO] JS动态抓取成功: {url}，共{len(ip_set)}个IP")
                    return ip_set
                else:
                    logging.warning(f"[AUTO] JS动态抓取无IP: {url}，第{attempt}次")
            except Exception as e:
                logging.error(f"[AUTO] JS动态抓取失败: {url}，第{attempt}次，错误: {e}")
            if attempt < js_retry:
                time.sleep(js_retry_interval)
        logging.error(f"[AUTO] JS动态抓取多次失败: {url}")
    else:
        logging.error(f"[AUTO] 未提供page对象，无法进行JS动态抓取: {url}")
    return set()

async def fetch_ip_static_async(url: str, pattern: str, timeout: int, session: aiohttp.ClientSession) -> tuple[str, Set[str], bool]:
    """
    异步静态页面抓取任务，返回(url, IP集合, 是否成功)。
    :param url: 目标URL
    :param pattern: IP正则
    :param timeout: 超时时间
    :param session: aiohttp.ClientSession
    :return: (url, IP集合, 是否成功)
    """
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status != 200:
                logging.warning(f"[ASYNC] 静态抓取失败: {url}，HTTP状态码: {response.status}")
                return (url, set(), False)
            text = await response.text()
            soup = BeautifulSoup(text, 'html.parser')
            elements = soup.find_all('tr') if soup.find_all('tr') else soup.find_all('li')
            ip_set: Set[str] = set()
            for element in elements:
                ip_set |= extract_ips(element.get_text(), pattern)
            if ip_set:
                logging.info(f"[ASYNC] 静态抓取成功: {url}，共{len(ip_set)}个IP")
                return (url, ip_set, True)
            else:
                logging.info(f"[ASYNC] 静态抓取无IP，加入JS动态队列: {url}")
                return (url, set(), False)
    except asyncio.TimeoutError:
        logging.warning(f"[ASYNC] 静态抓取超时: {url}，加入JS动态队列")
        return (url, set(), False)
    except Exception as e:
        logging.warning(f"[ASYNC] 静态抓取失败: {url}，错误: {e}，加入JS动态队列")
        return (url, set(), False)

async def async_static_crawl(sources: List[str], pattern: str, timeout: int) -> tuple[Set[str], List[str]]:
    """
    并发抓取所有静态页面，返回所有IP和需要JS动态抓取的URL。
    :param sources: URL列表
    :param pattern: IP正则
    :param timeout: 超时时间
    :return: (全部唯一IP集合, 需要JS动态抓取的URL列表)
    """
    all_ips: Set[str] = set()
    need_js_urls: List[str] = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_ip_static_async(url, pattern, timeout, session) for url in sources]
        results = await asyncio.gather(*tasks)
        for url, ip_set, success in results:
            if success:
                all_ips |= ip_set
            else:
                need_js_urls.append(url)
    return all_ips, need_js_urls

# ---------------- 主流程 ----------------
def main() -> None:
    """
    主程序入口，只从 config.yaml 读取配置，缺失项报错。
    1. 读取配置并校验
    2. 异步并发静态抓取
    3. Playwright 动态抓取（带重试）
    4. 结果去重并保存
    :return: None
    """
    config = load_config()
    sources = config['sources']
    pattern = config['pattern']
    output = config['output']
    timeout = config['timeout']
    log_file = config['log']
    max_workers = config['max_workers']
    log_level = config['log_level']
    js_retry = config['js_retry']
    js_retry_interval = config['js_retry_interval']

    setup_logging(log_file, log_level)
    # 若输出文件已存在，先删除
    if os.path.exists(output):
        try:
            os.remove(output)
        except Exception as e:
            logging.error(f"无法删除旧的输出文件: {output}，错误: {e}")

    # 异步并发静态抓取
    all_ips: Set[str] = set()
    need_js_urls: List[str] = []
    try:
        all_ips, need_js_urls = asyncio.run(async_static_crawl(sources, pattern, timeout))
    except Exception as e:
        logging.error(f"异步静态抓取流程异常: {e}")

    # 统一用一个浏览器实例处理所有需要JS动态的url
    if need_js_urls:
        session = get_retry_session(timeout)
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                try:
                    for url in need_js_urls:
                        all_ips |= fetch_ip_auto(url, pattern, timeout, session, page, js_retry, js_retry_interval)
                finally:
                    page.close()
                    browser.close()
        except Exception as e:
            logging.error(f"Playwright 启动或抓取失败: {e}")
    # 保存最终IP集合
    save_ips(all_ips, output)

if __name__ == '__main__':
    main() 