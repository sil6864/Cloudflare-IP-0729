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
import threading
from functools import wraps

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
            required = ['sources', 'pattern', 'output', 'timeout', 'log', 'max_workers', 'log_level', 'js_retry', 'js_retry_interval']
            for k in required:
                if k not in config:
                    raise KeyError(f'config.yaml 缺少必需字段: {k}')
            # 兼容sources为字符串或字典
            new_sources = []
            for item in config['sources']:
                if isinstance(item, str):
                    new_sources.append({'url': item, 'selector': None})
                elif isinstance(item, dict):
                    new_sources.append({'url': item['url'], 'selector': item.get('selector')})
                else:
                    raise ValueError('sources 列表元素必须为字符串或包含url/selector的字典')
            config['sources'] = new_sources
            # 其他默认值...（保持原有逻辑）
            if 'max_ips_per_url' not in config:
                config['max_ips_per_url'] = 0
            if 'per_url_limit_mode' not in config:
                config['per_url_limit_mode'] = 'random'
            if 'exclude_ips' not in config:
                config['exclude_ips'] = []
            if 'allowed_regions' not in config:
                config['allowed_regions'] = []
            if 'ip_geo_api' not in config:
                config['ip_geo_api'] = ''
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

def save_ips(ip_list: List[str], filename: str) -> None:
    """
    保存IP列表到文件，保持顺序。
    :param ip_list: IP列表
    :param filename: 输出文件名
    :return: None
    """
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            for ip in ip_list:
                file.write(ip + '\n')
        logging.info(f"共保存 {len(ip_list)} 个唯一IP到 {filename}")
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
def extract_ips_from_html(html: str, pattern: str, selector: str = None) -> List[str]:
    """
    智能提取IP，优先用selector，其次自动检测IP密集块，最后全局遍历。
    :param html: 网页HTML
    :param pattern: IP正则
    :param selector: 可选，CSS选择器
    :return: IP列表（顺序与页面一致）
    """
    soup = BeautifulSoup(html, 'html.parser')
    # 1. 优先用selector
    if selector:
        selected = soup.select(selector)
        if selected:
            ip_list = []
            for elem in selected:
                ip_list.extend(re.findall(pattern, elem.get_text()))
            if ip_list:
                logging.info(f"[EXTRACT] 使用selector '{selector}' 提取到{len(ip_list)}个IP")
                return list(dict.fromkeys(ip_list))
    # 2. 自动检测IP密集块
    candidates = []
    for tag in ['pre', 'code', 'table', 'div', 'section', 'article']:
        for elem in soup.find_all(tag):
            text = elem.get_text()
            ips = re.findall(pattern, text)
            if len(ips) >= 3:  # 至少3个IP才认为是候选
                candidates.append((len(ips), ips))
    if candidates:
        candidates.sort(reverse=True)
        ip_list = candidates[0][1]
        logging.info(f"[EXTRACT] 自动检测到IP密集块({len(ip_list)}个IP, tag优先级)")
        return list(dict.fromkeys(ip_list))
    # 3. 全局遍历
    all_text = soup.get_text()
    ip_list = re.findall(pattern, all_text)
    logging.info(f"[EXTRACT] 全局遍历提取到{len(ip_list)}个IP")
    return list(dict.fromkeys(ip_list))

def fetch_ip_auto(
    url: str,
    pattern: str,
    timeout: int,
    session: requests.Session,
    page: Optional[Page] = None,
    js_retry: int = 3,
    js_retry_interval: float = 2.0,
    selector: str = None
) -> List[str]:
    logging.info(f"[AUTO] 正在抓取: {url}")
    extracted_ips: List[str] = []
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    try:
        headers = {"User-Agent": user_agent}
        response = session.get(url, headers=headers)
        response.raise_for_status()
        text = response.text
        extracted_ips = extract_ips_from_html(text, pattern, selector)
        logging.info(f"[DEBUG] {url} 静态抓取前10个IP: {extracted_ips[:10]}")
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

async def fetch_ip_static_async(url: str, pattern: str, timeout: int, session: aiohttp.ClientSession, selector: str = None) -> tuple[str, List[str], bool]:
    """
    异步静态页面抓取任务，返回(url, IP列表 (有序且唯一), 是否成功)。
    :param url: 目标URL
    :param pattern: IP正则
    :param timeout: 超时时间
    :param session: aiohttp.ClientSession
    :param selector: 可选，CSS选择器
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
            ordered_unique_ips: List[str] = extract_ips_from_html(text, pattern, selector)
            logging.info(f"[DEBUG] {url} 静态抓取前10个IP: {ordered_unique_ips[:10]}")
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
def limit_ips(ip_collection: Union[List[str], Set[str]], max_count: int, mode: str = 'random') -> List[str]:
    """
    限制IP集合/列表的数量，根据指定模式返回有限的IP列表（有序）。
    :param ip_collection: 原始IP列表 (用于top模式，需保持顺序) 或集合 (用于random模式)
    :param max_count: 最大保留数量，0表示不限制
    :param mode: 限制模式，'random'为随机保留，'top'为保留页面靠前的
    :return: 限制后的IP列表（有序）
    """
    collection_list = list(ip_collection)
    collection_len = len(collection_list)
    if max_count <= 0 or collection_len <= max_count:
        return collection_list
    if mode == 'top':
        return collection_list[:max_count]
    elif mode == 'random':
        import random
        return random.sample(collection_list, max_count)
    else:
        logging.warning(f"[LIMIT] 未知的限制模式: {mode}，使用默认的随机模式")
        import random
        return random.sample(collection_list, max_count)

async def async_static_crawl(sources: List[Dict[str, str]], pattern: str, timeout: int, max_ips: int = 0, limit_mode: str = 'random') -> tuple[Dict[str, List[str]], List[str]]:
    """
    并发抓取所有静态页面，返回每个URL的IP列表和需要JS动态抓取的URL。
    :param sources: [{url, selector}]列表
    :param pattern: IP正则
    :param timeout: 超时时间
    :param max_ips: 每个URL最多保留的IP数量，0表示不限制
    :param limit_mode: 限制模式，'random'为随机保留，'top'为保留页面靠前的
    :return: (每个URL的IP列表字典, 需要JS动态抓取的URL列表)
    """
    url_ips_dict: Dict[str, List[str]] = {}
    need_js_urls: List[str] = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_ip_static_async(item['url'], pattern, timeout, session, item.get('selector')) for item in sources]
        results = await asyncio.gather(*tasks)
        for url, fetched_ip_list, success in results:
            if success:
                processed_ips_list: List[str]
                if max_ips > 0 and len(fetched_ip_list) > max_ips:
                    original_count = len(fetched_ip_list)
                    processed_ips_list = limit_ips(fetched_ip_list, max_ips, limit_mode)
                    logging.info(f"[LIMIT] URL {url} IP数量从 {original_count} 限制为 {len(processed_ips_list)}")
                else:
                    processed_ips_list = fetched_ip_list
                url_ips_dict[url] = processed_ips_list
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

# 速率限制装饰器（每秒最多N次）
def rate_limited(max_per_second):
    min_interval = 1.0 / float(max_per_second)
    lock = threading.Lock()
    last_time = [0.0]
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                elapsed = time.time() - last_time[0]
                wait = min_interval - elapsed
                if wait > 0:
                    time.sleep(wait)
                result = func(*args, **kwargs)
                last_time[0] = time.time()
                return result
        return wrapper
    return decorator

# ---------------- 新增：地区过滤相关函数 ----------------
@rate_limited(5)  # 默认每秒最多5次
def get_ip_region(ip: str, api_template: str, timeout: int = 5, max_retries: int = 3, retry_interval: float = 1.0) -> str:
    """
    查询IP归属地，返回国家/地区代码（如CN、US等），增加重试和降级机制。
    :param ip: IP地址
    :param api_template: API模板，{ip}会被替换
    :param timeout: 超时时间
    :param max_retries: 最大重试次数
    :param retry_interval: 重试间隔（秒）
    :return: 国家/地区代码（大写），失败返回空字符串
    """
    if not api_template:
        return ''
    url = api_template.replace('{ip}', ip)
    for attempt in range(1, max_retries + 1):
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
            logging.warning(f"[REGION] 查询IP归属地失败: {ip}, 第{attempt}次, 错误: {e}")
            if attempt < max_retries:
                time.sleep(retry_interval)
    # 多次失败降级，返回空字符串
    return ''

def filter_ips_by_region(ip_list: List[str], allowed_regions: list, api_template: str, timeout: int = 5) -> List[str]:
    """
    只保留指定地区的IP，保持顺序。
    :param ip_list: 原始IP列表
    :param allowed_regions: 允许的地区代码列表
    :param api_template: 归属地API模板
    :param timeout: 查询超时时间
    :return: 过滤后的IP列表
    """
    if not allowed_regions or not api_template:
        return ip_list
    allowed_set = set([r.upper() for r in allowed_regions if isinstance(r, str)])
    filtered = []
    for ip in ip_list:
        region = get_ip_region(ip, api_template, timeout, max_retries=3, retry_interval=1.0)
        if region in allowed_set:
            filtered.append(ip)
        else:
            logging.info(f"[REGION] 过滤掉IP: {ip}，归属地: {region if region else '未知'}")
    return filtered

def playwright_dynamic_fetch_worker(args):
    """
    单个线程任务：独立创建浏览器实例，抓取一个URL的动态IP。
    """
    url, pattern, timeout, js_retry, js_retry_interval, selector = args
    from playwright.sync_api import sync_playwright
    session = get_retry_session(timeout)
    result_ips = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            try:
                fetched_ip_list_dynamic = fetch_ip_auto(url, pattern, timeout, session, page, js_retry, js_retry_interval, selector)
                result_ips = fetched_ip_list_dynamic
            finally:
                page.close()
                browser.close()
    except Exception as e:
        logging.error(f"[THREAD] Playwright动态抓取失败: {url}, 错误: {e}")
    return url, result_ips

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
    sources = config['sources']  # [{url, selector}]
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
    exclude_ips_config = config['exclude_ips']

    setup_logging(log_file, log_level)
    if os.path.exists(output):
        try:
            os.remove(output)
        except Exception as e:
            logging.error(f"无法删除旧的输出文件: {output}，错误: {e}")

    url_ips_map: Dict[str, List[str]] = {}
    need_js_urls: List[Dict[str, str]] = []
    try:
        url_ips_map, need_js_urls_raw = asyncio.run(async_static_crawl(sources, pattern, timeout, max_ips_per_url, per_url_limit_mode))
        # need_js_urls_raw为url字符串列表，需转为[{url, selector}]
        need_js_urls = [item for item in sources if item['url'] in need_js_urls_raw]
    except Exception as e:
        logging.error(f"异步静态抓取流程异常: {e}")

    if need_js_urls:
        thread_num = min(4, len(need_js_urls))
        args_list = [
            (item['url'], pattern, timeout, js_retry, js_retry_interval, item.get('selector'))
            for item in need_js_urls
        ]
        url_ips_map_dynamic = {}
        with ThreadPoolExecutor(max_workers=thread_num) as executor:
            future_to_url = {executor.submit(playwright_dynamic_fetch_worker, args): args[0] for args in args_list}
            for future in as_completed(future_to_url):
                url, ips = future.result()
                url_ips_map_dynamic[url] = ips
        for url, ips in url_ips_map_dynamic.items():
            processed_ips_list: List[str]
            if max_ips_per_url > 0 and len(ips) > max_ips_per_url:
                original_count = len(ips)
                processed_ips_list = limit_ips(ips, max_ips_per_url, per_url_limit_mode)
                logging.info(f"[LIMIT] URL {url} IP数量从 {original_count} 限制为 {len(processed_ips_list)}")
            else:
                processed_ips_list = ips
            url_ips_map[url] = processed_ips_list

    is_excluded_func = build_ip_exclude_checker(exclude_ips_config)
    excluded_count = 0

    # 合并所有URL的IP列表，并应用排除规则，保持顺序
    merged_ips = []
    for url, ips_list_for_url in url_ips_map.items():
        original_count_before_exclude = len(ips_list_for_url)
        retained_ips = [ip for ip in ips_list_for_url if not is_excluded_func(ip)]
        excluded_in_source = original_count_before_exclude - len(retained_ips)
        if excluded_in_source > 0:
            logging.info(f"[EXCLUDE] URL {url} 排除了 {excluded_in_source} 个IP，保留 {len(retained_ips)} 个IP")
        excluded_count += excluded_in_source
        logging.info(f"URL {url} 贡献了 {len(retained_ips)} 个IP")
        merged_ips.extend(retained_ips)

    # 全局有序去重
    final_all_ips = list(dict.fromkeys(merged_ips))

    # 地区过滤
    allowed_regions = config.get('allowed_regions', [])
    ip_geo_api = config.get('ip_geo_api', '')
    if allowed_regions and ip_geo_api:
        before_region_count = len(final_all_ips)
        final_all_ips = filter_ips_by_region(final_all_ips, allowed_regions, ip_geo_api)
        after_region_count = len(final_all_ips)
        logging.info(f"[REGION] 地区过滤后，IP数量从 {before_region_count} 降至 {after_region_count}")

    # 保存最终IP列表
    save_ips(final_all_ips, output)
    logging.info(f"最终合并了 {len(url_ips_map)} 个URL的IP，排除了 {excluded_count} 个IP，共 {len(final_all_ips)} 个唯一IP")

if __name__ == '__main__':
    main() 