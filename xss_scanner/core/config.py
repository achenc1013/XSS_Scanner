#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
配置模块，负责管理扫描器的配置参数
"""

import os
import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger('xss_scanner')

class Config:
    """配置类，管理扫描器的所有配置选项"""
    
    def __init__(self):
        """初始化默认配置"""
        # 常规选项
        self.url = None
        self.depth = 2
        self.threads = 5
        self.timeout = 10
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.cookies = {}
        self.headers = {}
        self.proxy = None
        self.scan_level = 2
        self.scan_type = 'all'
        self.payload_level = 2
        self.output_file = None
        self.output_format = 'html'
        self.verbose = False
        self.no_color = False
        
        # 高级选项
        self.use_browser = False
        self.exploit = False
        self.custom_payloads = None
        self.exclude_pattern = None
        self.include_pattern = None
        self.auth = None
        
        # 内部使用
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.payloads_dir = os.path.join(self.base_dir, 'payloads')
    
    def load_from_args(self, args):
        """
        从命令行参数加载配置
        
        Args:
            args: 解析后的命令行参数
        """
        # 常规选项
        if args.url:
            self.url = args.url
            
        if args.depth:
            self.depth = args.depth
            
        if args.threads:
            self.threads = args.threads
            
        if args.timeout:
            self.timeout = args.timeout
            
        if args.user_agent:
            self.user_agent = args.user_agent
            
        if args.cookie:
            self._parse_cookies(args.cookie)
            
        if args.headers:
            self._parse_headers(args.headers)
            
        if args.proxy:
            self.proxy = args.proxy
            
        if args.scan_level:
            self.scan_level = args.scan_level
            
        if args.scan_type:
            self.scan_type = args.scan_type
            
        if args.payload_level:
            self.payload_level = args.payload_level
            
        if args.output:
            self.output_file = args.output
            
        if args.format:
            self.output_format = args.format
            
        self.verbose = args.verbose
        self.no_color = args.no_color
        
        # 高级选项
        self.use_browser = args.browser if hasattr(args, 'browser') else False
        self.exploit = args.exploit if hasattr(args, 'exploit') else False
        
        if hasattr(args, 'custom_payloads') and args.custom_payloads:
            self.custom_payloads = args.custom_payloads
            
        if hasattr(args, 'exclude') and args.exclude:
            self.exclude_pattern = args.exclude
            
        if hasattr(args, 'include') and args.include:
            self.include_pattern = args.include
            
        if hasattr(args, 'auth') and args.auth:
            self._parse_auth(args.auth)
    
    def load_from_file(self, config_file):
        """
        从配置文件加载配置
        
        Args:
            config_file: 配置文件路径
        """
        if not os.path.exists(config_file):
            logger.error(f"配置文件不存在: {config_file}")
            return False
            
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
                
            # 常规选项
            if 'url' in config_data:
                self.url = config_data['url']
                
            if 'depth' in config_data:
                self.depth = config_data['depth']
                
            if 'threads' in config_data:
                self.threads = config_data['threads']
                
            if 'timeout' in config_data:
                self.timeout = config_data['timeout']
                
            if 'user_agent' in config_data:
                self.user_agent = config_data['user_agent']
                
            if 'cookies' in config_data:
                self.cookies = config_data['cookies']
                
            if 'headers' in config_data:
                self.headers = config_data['headers']
                
            if 'proxy' in config_data:
                self.proxy = config_data['proxy']
                
            if 'scan_level' in config_data:
                self.scan_level = config_data['scan_level']
                
            if 'scan_type' in config_data:
                self.scan_type = config_data['scan_type']
                
            if 'payload_level' in config_data:
                self.payload_level = config_data['payload_level']
                
            if 'output_file' in config_data:
                self.output_file = config_data['output_file']
                
            if 'output_format' in config_data:
                self.output_format = config_data['output_format']
                
            if 'verbose' in config_data:
                self.verbose = config_data['verbose']
                
            if 'no_color' in config_data:
                self.no_color = config_data['no_color']
                
            # 高级选项
            if 'use_browser' in config_data:
                self.use_browser = config_data['use_browser']
                
            if 'exploit' in config_data:
                self.exploit = config_data['exploit']
                
            if 'custom_payloads' in config_data:
                self.custom_payloads = config_data['custom_payloads']
                
            if 'exclude_pattern' in config_data:
                self.exclude_pattern = config_data['exclude_pattern']
                
            if 'include_pattern' in config_data:
                self.include_pattern = config_data['include_pattern']
                
            if 'auth' in config_data:
                self.auth = config_data['auth']
                
            return True
        except Exception as e:
            logger.error(f"加载配置文件失败: {str(e)}")
            return False
    
    def save_to_file(self, config_file):
        """
        保存配置到文件
        
        Args:
            config_file: 配置文件路径
        """
        config_data = {
            'url': self.url,
            'depth': self.depth,
            'threads': self.threads,
            'timeout': self.timeout,
            'user_agent': self.user_agent,
            'cookies': self.cookies,
            'headers': self.headers,
            'proxy': self.proxy,
            'scan_level': self.scan_level,
            'scan_type': self.scan_type,
            'payload_level': self.payload_level,
            'output_file': self.output_file,
            'output_format': self.output_format,
            'verbose': self.verbose,
            'no_color': self.no_color,
            'use_browser': self.use_browser,
            'exploit': self.exploit,
            'custom_payloads': self.custom_payloads,
            'exclude_pattern': self.exclude_pattern,
            'include_pattern': self.include_pattern,
            'auth': self.auth
        }
        
        try:
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"保存配置文件失败: {str(e)}")
            return False
    
    def _parse_cookies(self, cookie_str):
        """
        解析Cookie字符串
        
        Args:
            cookie_str: Cookie字符串，格式：name1=value1; name2=value2
        """
        if not cookie_str:
            return
            
        try:
            self.cookies = {}
            for cookie in cookie_str.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    self.cookies[name] = value
        except Exception as e:
            logger.error(f"解析Cookie失败: {str(e)}")
    
    def _parse_headers(self, headers_str):
        """
        解析HTTP头字符串
        
        Args:
            headers_str: HTTP头字符串，格式：Header1:Value1;Header2:Value2
        """
        if not headers_str:
            return
            
        try:
            self.headers = {}
            for header in headers_str.split(';'):
                if ':' in header:
                    name, value = header.strip().split(':', 1)
                    self.headers[name] = value
        except Exception as e:
            logger.error(f"解析HTTP头失败: {str(e)}")
    
    def _parse_auth(self, auth_str):
        """
        解析基本认证字符串
        
        Args:
            auth_str: 基本认证字符串，格式：username:password
        """
        if not auth_str:
            return
            
        try:
            if ':' in auth_str:
                username, password = auth_str.split(':', 1)
                self.auth = {
                    'username': username,
                    'password': password
                }
        except Exception as e:
            logger.error(f"解析基本认证失败: {str(e)}")
    
    def get_payloads_file(self, payload_type):
        """
        获取指定类型的Payload文件路径
        
        Args:
            payload_type: Payload类型，如xss、sqli等
            
        Returns:
            str: Payload文件路径
        """
        # 如果指定了自定义Payload文件，则使用自定义文件
        if self.custom_payloads and os.path.exists(self.custom_payloads):
            return self.custom_payloads
            
        # 使用默认的Payload文件
        payload_file = f"{payload_type}_level{self.payload_level}.txt"
        payload_path = os.path.join(self.payloads_dir, payload_type, payload_file)
        
        if not os.path.exists(payload_path):
            logger.warning(f"Payload文件不存在: {payload_path}，使用默认Payload文件")
            payload_path = os.path.join(self.payloads_dir, payload_type, f"{payload_type}_level1.txt")
            
        return payload_path 