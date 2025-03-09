#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
扫描引擎核心模块
负责协调各种类型的扫描器和管理扫描过程
"""

import time
import logging
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

from xss_scanner.utils.crawler import Crawler
from xss_scanner.utils.http_client import HttpClient
from xss_scanner.scanners.xss_scanner import XSSScanner
from xss_scanner.scanners.csrf_scanner import CSRFScanner
from xss_scanner.scanners.sql_injection_scanner import SQLInjectionScanner
from xss_scanner.scanners.lfi_scanner import LFIScanner
from xss_scanner.scanners.rfi_scanner import RFIScanner
from xss_scanner.scanners.ssrf_scanner import SSRFScanner
from xss_scanner.scanners.xxe_scanner import XXEScanner

logger = logging.getLogger('xss_scanner')

class ScannerEngine:
    """扫描引擎核心类，负责协调不同类型的扫描器"""
    
    def __init__(self, config):
        """
        初始化扫描引擎
        
        Args:
            config: 配置对象，包含扫描参数
        """
        self.config = config
        self.http_client = HttpClient(
            timeout=config.timeout,
            user_agent=config.user_agent,
            proxy=config.proxy,
            cookies=config.cookies,
            headers=config.headers
        )
        self.crawler = Crawler(
            http_client=self.http_client,
            max_depth=config.depth,
            threads=config.threads,
            exclude_pattern=config.exclude_pattern,
            include_pattern=config.include_pattern
        )
        
        # 初始化各种扫描器
        self.scanners = []
        self.initialize_scanners()
        
        # 线程池
        self.thread_pool = ThreadPoolExecutor(max_workers=config.threads)
        
        # 存储扫描结果
        self.results = {
            'target': None,
            'start_time': None,
            'end_time': None,
            'scan_info': {
                'scan_level': config.scan_level,
                'scan_type': config.scan_type,
                'threads': config.threads,
                'depth': config.depth
            },
            'vulnerabilities': [],
            'statistics': {
                'pages_scanned': 0,
                'forms_tested': 0,
                'parameters_tested': 0,
                'vulnerabilities_found': 0
            }
        }
    
    def initialize_scanners(self):
        """初始化所有扫描器"""
        # 添加XSS扫描器
        self.scanners.append(XSSScanner(
            http_client=self.http_client,
            payload_level=self.config.payload_level,
            use_browser=self.config.use_browser
        ))
        
        # 根据配置添加其他类型的扫描器
        if self.config.scan_type in ['all', 'csrf']:
            self.scanners.append(CSRFScanner(self.http_client))
            
        if self.config.scan_type in ['all', 'sqli']:
            self.scanners.append(SQLInjectionScanner(self.http_client))
            
        if self.config.scan_type in ['all', 'lfi']:
            self.scanners.append(LFIScanner(self.http_client))
            
        if self.config.scan_type in ['all', 'rfi']:
            self.scanners.append(RFIScanner(self.http_client))
            
        if self.config.scan_type in ['all', 'ssrf']:
            self.scanners.append(SSRFScanner(self.http_client))
            
        if self.config.scan_type in ['all', 'xxe']:
            self.scanners.append(XXEScanner(self.http_client))
    
    def scan(self, target_url):
        """
        对目标进行扫描
        
        Args:
            target_url: 目标URL
            
        Returns:
            dict: 扫描结果
        """
        self.results['target'] = target_url
        self.results['start_time'] = time.time()
        
        # 爬取目标站点
        logger.info(f"开始爬取目标站点: {target_url}")
        pages = self.crawler.crawl(target_url)
        self.results['statistics']['pages_scanned'] = len(pages)
        logger.info(f"爬取完成，发现 {len(pages)} 个页面")
        
        # 对每个页面进行扫描
        for page in pages:
            logger.debug(f"扫描页面: {page['url']}")
            
            # 对页面中的表单进行测试
            for form in page.get('forms', []):
                self.results['statistics']['forms_tested'] += 1
                self._scan_form(page['url'], form)
            
            # 对URL参数进行测试
            if page.get('params', []):
                self._scan_params(page['url'], page['params'])
                self.results['statistics']['parameters_tested'] += len(page['params'])
        
        # 如果配置了漏洞利用，则尝试利用发现的漏洞
        if self.config.exploit and self.results['vulnerabilities']:
            self._exploit_vulnerabilities()
        
        self.results['end_time'] = time.time()
        self.results['statistics']['vulnerabilities_found'] = len(self.results['vulnerabilities'])
        
        return self.results
    
    def _scan_form(self, url, form):
        """
        扫描表单
        
        Args:
            url: 页面URL
            form: 表单信息
        """
        logger.debug(f"扫描表单: {form.get('id', 'unknown')}")
        
        # 对表单中的每个输入字段进行测试
        for field in form.get('fields', []):
            if field['type'] in ['text', 'search', 'url', 'email', 'password', 'tel', 'number']:
                for scanner in self.scanners:
                    # 跳过不适用于表单的扫描器
                    if not scanner.can_scan_form():
                        continue
                        
                    result = scanner.scan_form(url, form, field)
                    if result:
                        self.results['vulnerabilities'].append(result)
                        logger.warning(f"在表单中发现漏洞: {result['type']} - {result['description']}")
    
    def _scan_params(self, url, params):
        """
        扫描URL参数
        
        Args:
            url: 页面URL
            params: URL参数列表
        """
        logger.debug(f"扫描URL参数: {', '.join(params)}")
        
        for param in params:
            for scanner in self.scanners:
                # 跳过不适用于URL参数的扫描器
                if not scanner.can_scan_params():
                    continue
                    
                result = scanner.scan_parameter(url, param)
                if result:
                    self.results['vulnerabilities'].append(result)
                    logger.warning(f"在URL参数中发现漏洞: {result['type']} - {result['description']}")
    
    def _exploit_vulnerabilities(self):
        """尝试利用发现的漏洞"""
        logger.info("尝试利用发现的漏洞...")
        
        for vuln in self.results['vulnerabilities']:
            # 根据漏洞类型选择合适的利用模块
            exploit_module = self._get_exploit_module(vuln['type'])
            if exploit_module:
                exploit_result = exploit_module.exploit(vuln)
                if exploit_result:
                    vuln['exploit_result'] = exploit_result
                    logger.warning(f"成功利用漏洞: {vuln['type']} - {exploit_result['description']}")
    
    def _get_exploit_module(self, vuln_type):
        """
        根据漏洞类型获取对应的利用模块
        
        Args:
            vuln_type: 漏洞类型
            
        Returns:
            对应的利用模块实例
        """
        if vuln_type == 'XSS':
            from xss_scanner.exploits.xss_exploit import XSSExploit
            return XSSExploit(self.http_client)
        elif vuln_type == 'CSRF':
            from xss_scanner.exploits.csrf_exploit import CSRFExploit
            return CSRFExploit(self.http_client)
        elif vuln_type == 'SQL_INJECTION':
            from xss_scanner.exploits.sqli_exploit import SQLInjectionExploit
            return SQLInjectionExploit(self.http_client)
        elif vuln_type == 'LFI':
            from xss_scanner.exploits.lfi_exploit import LFIExploit
            return LFIExploit(self.http_client)
        elif vuln_type == 'RFI':
            from xss_scanner.exploits.rfi_exploit import RFIExploit
            return RFIExploit(self.http_client)
        elif vuln_type == 'SSRF':
            from xss_scanner.exploits.ssrf_exploit import SSRFExploit
            return SSRFExploit(self.http_client)
        elif vuln_type == 'XXE':
            from xss_scanner.exploits.xxe_exploit import XXEExploit
            return XXEExploit(self.http_client)
        return None 