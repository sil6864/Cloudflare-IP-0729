# -*- coding: utf-8 -*-
import os
import re
import logging
import argparse
import time
from typing import List, Set, Optional, Dict, Any, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress  # 新增: 用于支持CIDR格式网段判断

import requests
from requests.adapters import HTTPAdapter, Retry
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, Page
import asyncio
import aiohttp
import json

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
            
            # 新增配置项默认值
            if 'max_ips_per_url' not in config:
                config['max_ips_per_url'] = 0  # 默认不限制
            if 'per_url_limit_mode' not in config:
                config['per_url_limit_mode'] = 'random'  # 默认随机保留
            if 'exclude_ips' not in config:
                config['exclude_ips'] = []  # 默认不排除任何IP
            # 新增地区过滤相关配置
            if 'allowed_regions' not in config:
                config['allowed_regions'] = []  # 默认不限制地区
            if 'ip_geo_api' not in config:
                config['ip_geo_api'] = ''  # 默认不查归属地
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
def extract_ips(text: str, pattern: str) -> List[str]:
    """
    从文本中提取所有IP地址，并保持原始顺序。
    :param text: 输入文本
    :param pattern: IP正则表达式
    :return: IP列表 (按找到的顺序)
    """
    return re.findall(pattern, text)

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
) -> List[str]:
    logging.info(f"[AUTO] 正在抓取: {url}")
    extracted_ips: List[str] = []
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    try:
        headers = {"User-Agent": user_agent}
        response = session.get(url, headers=headers)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()
        text = response.text
        if 'text/html' in content_type or '<html' in text.lower():
            soup = BeautifulSoup(text, 'html.parser')
            ip_list: List[str] = []
            table = soup.find('table')
            if table:
                for row in table.find_all('tr'):
                    for cell in row.find_all('td'):
                        ip_list.extend(extract_ips(cell.get_text(), pattern))
            else:
                elements = soup.find_all('tr') if soup.find_all('tr') else soup.find_all('li')
                for element in elements:
                    ip_list.extend(extract_ips(element.get_text(), pattern))
            extracted_ips = list(dict.fromkeys(ip_list))
            logging.info(f"[DEBUG] {url} 静态抓取前10个IP: {extracted_ips[:10]}")
        else:
            ip_list = extract_ips(text, pattern)
            extracted_ips = list(dict.fromkeys(ip_list))
            logging.info(f"[DEBUG] {url} 纯文本抓取前10个IP: {extracted_ips[:10]}")
        if extracted_ips:
            logging.info(f"[AUTO] 静态抓取成功: {url}，共{len(extracted_ips)}个IP")
            return extracted_ips
        else:
            logging.info(f"[AUTO] 静态抓取无IP，尝试JS动态: {url}")
    except requests.RequestException as e:
        logging.warning(f"[AUTO] 静态抓取失败: {url}，网络错误: {e}，尝试JS动态")
    except Exception as e:
        logging.warning(f"[AUTO] 静态抓取失败: {url}，解析错误: {e}，尝试JS动态")
    if page is not None:
        try:
            page.set_extra_http_headers({"User-Agent": user_agent})
        except Exception:
            pass
        found_ip_list = []
        def handle_response(response):
            try:
                text = response.text()
                ip_list = extract_ips(text, pattern)
                if len(ip_list) >= 10:  # 阈值可调
                    found_ip_list.extend(ip_list)
            except Exception:
                pass
        page.on("response", handle_response)
        for attempt in range(1, js_retry + 1):
            try:
                page.goto(url, timeout=30000)
                page.wait_for_timeout(5000)
                if found_ip_list:
                    found_ip_list = list(dict.fromkeys(found_ip_list))
                    logging.info(f"[AUTO] 监听接口自动提取到 {len(found_ip_list)} 个IP: {found_ip_list[:10]}")
                    return found_ip_list
                page_content = page.content()
                if '<html' in page_content.lower():
                    soup = BeautifulSoup(page_content, 'html.parser')
                    ip_list: List[str] = []
                    table = soup.find('table')
                    if table:
                        for row in table.find_all('tr'):
                            for cell in row.find_all('td'):
                                ip_list.extend(extract_ips(cell.get_text(), pattern))
                    else:
                        elements = soup.find_all('tr') if soup.find_all('tr') else soup.find_all('li')
                        for element in elements:
                            ip_list.extend(extract_ips(element.get_text(), pattern))
                    extracted_ips = list(dict.fromkeys(ip_list))
                    logging.info(f"[DEBUG] {url} JS动态抓取前10个IP: {extracted_ips[:10]}")
                else:
                    ip_list = extract_ips(page_content, pattern)
                    extracted_ips = list(dict.fromkeys(ip_list))
                    logging.info(f"[DEBUG] {url} JS动态纯文本前10个IP: {extracted_ips[:10]}")
                if extracted_ips:
                    logging.info(f"[AUTO] JS动态抓取成功: {url}，共{len(extracted_ips)}个IP")
                    return extracted_ips
                else:
                    logging.warning(f"[AUTO] JS动态抓取无IP: {url}，第{attempt}次")
            except Exception as e:
                logging.error(f"[AUTO] JS动态抓取失败: {url}，第{attempt}次，错误: {e}")
            if attempt < js_retry:
                time.sleep(js_retry_interval)
        logging.error(f"[AUTO] JS动态抓取多次失败: {url}")
    else:
        logging.error(f"[AUTO] 未提供page对象，无法进行JS动态抓取: {url}")
    return []

async def fetch_ip_static_async(url: str, pattern: str, timeout: int, session: aiohttp.ClientSession) -> tuple[str, List[str], bool]:
    """
    异步静态页面抓取任务，返回(url, IP列表 (有序且唯一), 是否成功)。
    :param url: 目标URL
    :param pattern: IP正则
    :param timeout: 超时时间
    :param session: aiohttp.ClientSession
    :return: (url, IP列表 (有序且唯一), 是否成功)
    """
    try:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        headers = {"User-Agent": user_agent}
        async with session.get(url, timeout=timeout, headers=headers) as response:
            if response.status != 200:
                logging.warning(f"[ASYNC] 静态抓取失败: {url}，HTTP状态码: {response.status}")
                return (url, [], False)
            text = await response.text()
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' in content_type or '<html' in text.lower():
                soup = BeautifulSoup(text, 'html.parser')
                ip_list: List[str] = []
                table = soup.find('table')
                if table:
                    for row in table.find_all('tr'):
                        for cell in row.find_all('td'):
                            ip_list.extend(extract_ips(cell.get_text(), pattern))
                else:
                    elements = soup.find_all('tr') if soup.find_all('tr') else soup.find_all('li')
                    for element in elements:
                        ip_list.extend(extract_ips(element.get_text(), pattern))
                ordered_unique_ips: List[str] = list(dict.fromkeys(ip_list))
                logging.info(f"[DEBUG] {url} 静态抓取前10个IP: {ordered_unique_ips[:10]}")
            else:
                ip_list = extract_ips(text, pattern)
                ordered_unique_ips: List[str] = list(dict.fromkeys(ip_list))
                logging.info(f"[DEBUG] {url} 纯文本抓取前10个IP: {ordered_unique_ips[:10]}")
            if ordered_unique_ips:
                logging.info(f"[ASYNC] 静态抓取成功: {url}，共{len(ordered_unique_ips)}个IP")
                return (url, ordered_unique_ips, True)
            else:
                logging.info(f"[ASYNC] 静态抓取无IP，加入JS动态队列: {url}")
                return (url, [], False)
    except asyncio.TimeoutError:
        logging.warning(f"[ASYNC] 静态抓取超时: {url}，加入JS动态队列")
        return (url, [], False)
    except Exception as e:
        logging.warning(f"[ASYNC] 静态抓取失败: {url}，错误: {e}，加入JS动态队列")
        return (url, [], False)

# ---------------- 新增：IP数量限制 ----------------
def limit_ips(ip_collection: Union[List[str], Set[str]], max_count: int, mode: str = 'random') -> Set[str]:
    """
    限制IP集合/列表的数量，根据指定模式返回有限的IP集合。
    :param ip_collection: 原始IP列表 (用于top模式，需保持顺序) 或集合 (用于random模式)
    :param max_count: 最大保留数量，0表示不限制
    :param mode: 限制模式，'random'为随机保留，'top'为保留页面靠前的
    :return: 限制后的IP集合
    """
    collection_len = len(ip_collection)
    
    if max_count <= 0 or collection_len <= max_count:
        # 如果不限制或数量已在限制内，确保返回的是Set类型
        if isinstance(ip_collection, list):
            return set(ip_collection)
        return ip_collection # 已经是Set

    if mode == 'top':
        if isinstance(ip_collection, list):
            # 如果是列表（期望的输入），按原始顺序取top N
            return set(ip_collection[:max_count])
        else:
            # 如果错误地传入了set，则退回按字典序排序（旧行为）
            logging.warning("[LIMIT] Top mode 收到 Set 类型输入，将按字典序排序选取。")
            return set(sorted(list(ip_collection))[:max_count])
    elif mode == 'random':
        # 随机模式，确保输入是列表以便采样
        return set(random.sample(list(ip_collection), max_count))
    else:
        logging.warning(f"[LIMIT] 未知的限制模式: {mode}，使用默认的随机模式")
        return set(random.sample(list(ip_collection), max_count))

async def async_static_crawl(sources: List[str], pattern: str, timeout: int, max_ips: int = 0, limit_mode: str = 'random') -> tuple[Dict[str, Set[str]], List[str]]:
    """
    并发抓取所有静态页面，返回每个URL的IP集合和需要JS动态抓取的URL。
    :param sources: URL列表
    :param pattern: IP正则
    :param timeout: 超时时间
    :param max_ips: 每个URL最多保留的IP数量，0表示不限制
    :param limit_mode: 限制模式，'random'为随机保留，'top'为保留页面靠前的
    :return: (每个URL的IP集合字典, 需要JS动态抓取的URL列表)
    """
    url_ips_dict: Dict[str, Set[str]] = {} # 修改变量名以避免与外部的url_ips混淆
    need_js_urls: List[str] = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_ip_static_async(url, pattern, timeout, session) for url in sources]
        results = await asyncio.gather(*tasks)
        for url, fetched_ip_list, success in results: # fetched_ip_list 是 List[str]
            if success:
                processed_ips_set: Set[str]
                if max_ips > 0 and len(fetched_ip_list) > max_ips:
                    original_count = len(fetched_ip_list)
                    if limit_mode == 'top':
                        # top模式直接使用有序列表
                        processed_ips_set = limit_ips(fetched_ip_list, max_ips, limit_mode)
                    else:
                        # random或其他模式，先转为set再处理
                        processed_ips_set = limit_ips(set(fetched_ip_list), max_ips, limit_mode)
                    logging.info(f"[LIMIT] URL {url} IP数量从 {original_count} 限制为 {len(processed_ips_set)}")
                else:
                    # 未超限或不限制，直接用抓取到的列表（转为set）
                    processed_ips_set = set(fetched_ip_list)
                url_ips_dict[url] = processed_ips_set
            else:
                need_js_urls.append(url)
    return url_ips_dict, need_js_urls

# ---------------- 新增：IP排除功能 ----------------
def build_ip_exclude_checker(exclude_patterns: List[str]) -> callable:
    """
    构建IP排除检查器，支持精确匹配和CIDR格式网段匹配。
    :param exclude_patterns: 排除IP/网段列表
    :return: 检查函数，接收IP字符串，返回是否应该排除
    """
    if not exclude_patterns:
        # 没有排除规则，返回始终为False的函数
        return lambda ip: False
    
    # 预处理排除列表，分为精确匹配和网段匹配
    exact_ips = set()
    networks = []
    
    for pattern in exclude_patterns:
        pattern = pattern.strip()
        if '/' in pattern:
            # CIDR格式网段
            try:
                networks.append(ipaddress.ip_network(pattern, strict=False))
            except ValueError as e:
                logging.warning(f"无效的CIDR格式网段: {pattern}, 错误: {e}")
        else:
            # 精确匹配的IP
            exact_ips.add(pattern)
    
    def is_excluded(ip: str) -> bool:
        """
        检查IP是否应被排除。
        :param ip: IP地址字符串
        :return: 如果应该排除则为True，否则为False
        """
        # 先检查精确匹配
        if ip in exact_ips:
            return True
        
        # 再检查网段匹配
        if networks:
            try:
                ip_obj = ipaddress.ip_address(ip)
                return any(ip_obj in network for network in networks)
            except ValueError:
                logging.warning(f"无效的IP地址: {ip}")
        
        return False
    
    return is_excluded

# ---------------- 新增：地区过滤相关函数 ----------------
def get_ip_region(ip: str, api_template: str, timeout: int = 5) -> str:
    """
    查询IP归属地，返回国家/地区代码（如CN、US等）。
    :param ip: IP地址
    :param api_template: API模板，{ip}会被替换
    :param timeout: 超时时间
    :return: 国家/地区代码（大写），失败返回空字符串
    """
    if not api_template:
        return ''
    url = api_template.replace('{ip}', ip)
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        # 兼容常见API返回格式
        for key in ['countryCode', 'country_code', 'country', 'countrycode']:
            if key in data:
                val = data[key]
                if isinstance(val, str) and len(val) <= 3:
                    return val.upper()
        # ipinfo.io等
        if 'country' in data and isinstance(data['country'], str):
            return data['country'].upper()
    except Exception as e:
        logging.warning(f"[REGION] 查询IP归属地失败: {ip}, 错误: {e}")
    return ''

def filter_ips_by_region(ip_set: Set[str], allowed_regions: list, api_template: str, timeout: int = 5) -> Set[str]:
    """
    只保留指定地区的IP。
    :param ip_set: 原始IP集合
    :param allowed_regions: 允许的地区代码列表
    :param api_template: 归属地API模板
    :param timeout: 查询超时时间
    :return: 过滤后的IP集合
    """
    if not allowed_regions or not api_template:
        return ip_set
    allowed_set = set([r.upper() for r in allowed_regions if isinstance(r, str)])
    filtered = set()
    for ip in ip_set:
        region = get_ip_region(ip, api_template, timeout)
        if region in allowed_set:
            filtered.add(ip)
        else:
            logging.info(f"[REGION] 过滤掉IP: {ip}，归属地: {region if region else '未知'}")
    return filtered

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
    max_ips_per_url = config['max_ips_per_url']
    per_url_limit_mode = config['per_url_limit_mode']
    exclude_ips_config = config['exclude_ips'] # 重命名以区分函数
    
    setup_logging(log_file, log_level)
    # 若输出文件已存在，先删除
    if os.path.exists(output):
        try:
            os.remove(output)
        except Exception as e:
            logging.error(f"无法删除旧的输出文件: {output}，错误: {e}")

    # url_ips 存储每个 URL 最终筛选后的 IP 集合
    url_ips_map: Dict[str, Set[str]] = {} # 修改变量名以避免混淆
    need_js_urls: List[str] = []
    try:
        # async_static_crawl 返回的已经是限制和处理后的 Dict[str, Set[str]]
        url_ips_map, need_js_urls = asyncio.run(async_static_crawl(sources, pattern, timeout, max_ips_per_url, per_url_limit_mode))
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
                        # fetch_ip_auto 返回 List[str]
                        fetched_ip_list_dynamic = fetch_ip_auto(url, pattern, timeout, session, page, js_retry, js_retry_interval)
                        processed_ips_set_dynamic: Set[str]
                        # 应用IP数量限制
                        if max_ips_per_url > 0 and len(fetched_ip_list_dynamic) > max_ips_per_url:
                            original_count = len(fetched_ip_list_dynamic)
                            if per_url_limit_mode == 'top':
                                # top模式直接使用有序列表
                                processed_ips_set_dynamic = limit_ips(fetched_ip_list_dynamic, max_ips_per_url, per_url_limit_mode)
                            else:
                                # random或其他模式，先转为set再处理
                                processed_ips_set_dynamic = limit_ips(set(fetched_ip_list_dynamic), max_ips_per_url, per_url_limit_mode)
                            logging.info(f"[LIMIT] URL {url} IP数量从 {original_count} 限制为 {len(processed_ips_set_dynamic)}")
                        else:
                            processed_ips_set_dynamic = set(fetched_ip_list_dynamic)
                        url_ips_map[url] = processed_ips_set_dynamic # 添加或更新动态抓取的IP
                finally:
                    page.close()
                    browser.close()
        except Exception as e:
            logging.error(f"Playwright 启动或抓取失败: {e}")
            
    # 构建IP排除检查器
    is_excluded_func = build_ip_exclude_checker(exclude_ips_config) # 使用重命名的配置变量
    excluded_count = 0
            
    # 合并所有URL的IP集合，并应用排除规则
    final_all_ips = set() # 修改变量名
    for url, ips_set_for_url in url_ips_map.items(): # ips_set_for_url 是 Set[str]
        # 过滤排除的IP
        original_count_before_exclude = len(ips_set_for_url)
        # 应用排除规则到每个 URL 的 IP 集合上
        retained_ips = {ip for ip in ips_set_for_url if not is_excluded_func(ip)}
        excluded_in_source = original_count_before_exclude - len(retained_ips)
        
        if excluded_in_source > 0:
            logging.info(f"[EXCLUDE] URL {url} 排除了 {excluded_in_source} 个IP，保留 {len(retained_ips)} 个IP")
        excluded_count += excluded_in_source
        
        logging.info(f"URL {url} 贡献了 {len(retained_ips)} 个IP")
        final_all_ips |= retained_ips
        
    # 地区过滤
    allowed_regions = config.get('allowed_regions', [])
    ip_geo_api = config.get('ip_geo_api', '')
    if allowed_regions and ip_geo_api:
        before_region_count = len(final_all_ips)
        final_all_ips = filter_ips_by_region(final_all_ips, allowed_regions, ip_geo_api)
        after_region_count = len(final_all_ips)
        logging.info(f"[REGION] 地区过滤后，IP数量从 {before_region_count} 降至 {after_region_count}")
        
    # 保存最终IP集合
    save_ips(final_all_ips, output)
    logging.info(f"最终合并了 {len(url_ips_map)} 个URL的IP，排除了 {excluded_count} 个IP，共 {len(final_all_ips)} 个唯一IP")

if __name__ == '__main__':
    main() 