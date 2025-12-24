# Upload_Auto_Fuzz

Burp Suite 文件上传漏洞自动化测试插件

![Burp Suite Extension](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Version](https://img.shields.io/badge/Version-v1.2.0-blue)

## 简介

一个用于测试文件上传功能安全性的 Burp Suite 插件。通过 Intruder 模块自动生成各类绕过 payload，覆盖常见的文件上传限制场景。

## v1.2.0 更新内容

**架构重构**
- 采用策略模式重写，代码结构更清晰
- 新增配置面板，可自定义测试范围
- 支持 Burp Suite 深色主题

**功能增强**
- 新增后端语言选择（PHP/ASP/ASPX/JSP）
- 新增 14 种独立的 Fuzz 策略，可单独启用/禁用
- payload 数量提升至 1000+
- 优化去重算法，减少无效请求

**新增测试点**
- 双写绕过：`pphphp`、`aspasp`
- form-data 污染：多分号、脏数据替换
- 未闭合引号：`filename="shell.php`
- URL 编码 Content-Type：`image%2Fphp`
- 配置文件内容注入：.htaccess / .user.ini 实际利用内容


## 测试覆盖范围

### 后缀绕过
- 可执行扩展名变体：php3/php5/phtml/phar/asa/cer/ashx/jspx 等
- 大小写混淆：pHp、PhP、aSp、JsP
- 双写绕过：pphphp、aspasp、jspjsp
- 特殊字符：空格、点号、分号（`shell.php.`、`shell.php;.jpg`）
- 空字节截断：`shell.php%00.jpg`

### 请求头操控
- Content-Disposition 大小写：`ConTENT-DisPoSition`
- form-data 污染：删除、替换为脏数据、多分号
- filename 参数：双 filename、空 filename、未闭合引号、多等号
- 换行注入：`filename\n="shell.php"`

### Content-Type 绕过
- MIME 类型伪造：image/gif、image/png、application/octet-stream
- URL 编码：`image%2Fgif`、`image%2Fphp`
- 双重 Content-Type 头
- 大小写变换

### 系统特性利用

**Windows**
- NTFS 数据流：`shell.php::$DATA`
- IIS 分号解析：`shell.asp;.jpg`
- 保留设备名：con.php、aux.asp
- 尾部空格/点号

**Linux**
- Apache 多扩展名：`shell.php.jpg`
- 路径穿越：`../shell.php`
- 隐藏文件：`.shell.php`

### 编码绕过
- URL 编码扩展名：`%70%68%70`
- 双重 URL 编码
- MIME 编码（RFC 2047）
- Unicode 字符替换

### 配置文件上传
- `.htaccess`：SetHandler 解析任意文件为 PHP
- `.user.ini`：auto_prepend_file 文件包含
- `web.config`：IIS handlers 配置

### 文件内容
- 魔术字节注入：GIF89a、PNG 头、PDF 头
- WebShell 内容（可选）
- 图片头 + WebShell 组合


## 安装

1. 下载 `Upload_Auto_Fuzz.py`
2. Burp Suite → Extender → Add
3. Extension type 选择 Python
4. 选择下载的文件，点击 Next

> 需要配置 Jython，参考 [Burp 官方文档](https://portswigger.net/burp/documentation/desktop/extensions)

## 使用方法

### 配置（可选）

安装后在 Burp 顶部菜单栏会出现 `Upload Fuzz` 标签页：

- **Target Backend Languages**：选择目标后端语言
- **Fuzzing Strategies**：启用/禁用特定测试策略
- **Include WebShell Content**：是否在 payload 中包含实际 WebShell 代码

### 测试步骤

1. 抓取文件上传请求，发送到 Intruder

2. 选中需要 Fuzz 的区域（建议选中整个文件部分）：

   ```
   Content-Disposition: form-data; name="file"; filename="test.jpg"
   Content-Type: image/jpeg

   [文件内容]
   ```

   ![positions](./assets/11.png)

3. Payloads 标签页配置：
   - Payload type: `Extension-generated`
   - Select generator: `Upload_Auto_Fuzz 1.2.0`

   ![payloads](./assets/13.png)

4. **重要**：取消勾选 `Payload Encoding`

   ![encoding](./assets/12.png)

5. 开始攻击，根据响应长度/状态码筛选结果

## Payload 示例

| 类型 | 示例 | 说明 |
|------|------|------|
| 后缀绕过 | `shell.phtml` | PHP 替代扩展名 |
| 双写绕过 | `shell.pphphp` | 绕过单次替换过滤 |
| 分号截断 | `shell.asp;.jpg` | IIS 解析特性 |
| 空字节 | `shell.php%00.jpg` | 老版本语言截断 |
| 双扩展名 | `shell.jpg.php` | Apache 解析顺序 |
| NTFS 流 | `shell.php::$DATA` | Windows 特性 |
| 双 filename | `filename="1.jpg";filename="shell.php"` | 参数污染 |
| 未闭合引号 | `filename="shell.php` | 解析差异 |
| 配置文件 | `.htaccess` | 修改服务器解析规则 |


## 策略说明

| 策略 | 描述 | 默认 |
|------|------|------|
| suffix | 后缀绕过，扩展名变体 | ✓ |
| content_disposition | Content-Disposition 头操控 | ✓ |
| content_type | Content-Type 伪造 | ✓ |
| windows_features | Windows 系统特性（ADS、保留名） | ✓ |
| linux_features | Linux 特性（路径穿越、多扩展名） | ✓ |
| magic_bytes | 文件头魔术字节 | ✓ |
| null_byte | 空字节截断 | ✓ |
| double_extension | 双/多扩展名 | ✓ |
| case_variation | 大小写变换 | ✓ |
| special_chars | 特殊字符注入 | ✓ |
| encoding | 编码绕过（URL/Unicode） | ✓ |
| waf_bypass | WAF 绕过技术 | ✓ |
| webshell_content | WebShell 内容注入 | ✓ |
| config_files | 配置文件上传 | ✓ |

## 注意事项

- 部分 payload 可能触发 WAF 告警，建议在测试环境使用
- WebShell 内容功能默认开启，正式测试前确认授权
- 某些 payload 依赖特定服务器配置才能生效

## 更新日志

- **v1.2.0** - 架构重构，新增配置面板，策略模式，1000+ payload
- **v1.1.0** - 新增云环境绕过、AI 防御对抗模块
- **v1.0.0** - 初始版本，基础 Fuzz 功能

## 作者

T3nk0

## 免责声明

本工具仅用于授权的安全测试。使用者需确保已获得目标系统的测试授权，并遵守相关法律法规。作者不对任何滥用行为负责。


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=T3nk0/Upload_Auto_Fuzz&type=Date)](https://star-history.com/#T3nk0/Upload_Auto_Fuzz&Date)
