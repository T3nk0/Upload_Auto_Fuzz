# Upload_Auto_Fuzz - Burp Suite 文件上传漏洞Fuzz插件

![Burp Suite Extension](https://img.shields.io/badge/Burp%20Suite-Extension-orange)

## 功能概述

本Burp Suite插件专为文件上传漏洞检测设计，提供自动化Fuzz测试，共300+条payload。效果如图

![14](./assets/14.png)

主要包含以下攻击向量：

### 🛡️ WAF绕过技术
- **后缀变异**：ASP/ASPX/PHP/JSP后缀混淆（空字节、双扩展名、特殊字符等）
- **内容编码**：MIME编码、Base64编码、RFC 2047规范绕过
- **协议攻击**：HTTP头拆分、分块传输编码、协议走私

### 🖥️ 系统特性利用
- **Windows特性**：
  - NTFS数据流（::$DATA）
  - 保留设备名（CON, AUX）
  - 长文件名截断
- **Linux特性**：
  - Apache多级扩展解析
  - 路径遍历尝试
  - 点号截断攻击

### 🎭 内容欺骗
- 魔术字节注入（GIF/PNG/PDF头）
- SVG+XSS组合攻击
- 文件内容混淆（注释插入、编码变异）

## 安装方法

1. 确保已安装Burp Suite Professional
2. 在Burp Extender中点击"Add"
3. 选择下载的`Upload_Auto_Fuzz.py`文件
4. 点击"Next"直到安装完成

## 使用指南

1. 拦截文件上传请求

2. 右键请求内容 → "Send to Intruder"

3. Positions内将Content-Disposition开始，到文件内容结束的数据作为fuzz对象，如图

   ![11](./assets/11.png)

4. 在Intruder的"Payloads"标签中选择：
   ```bash
   Payload type: Extension-generated
   Select generator: upload_auto_fuzz
   ```

   ![13](./assets/13.png)

5. 取消Payload encoding选择框，如图

   ![12](./assets/12.png)

6. 开始攻击并分析响应

## Payload分类说明

| 类别                | 样本payload                          | 检测目标               |
|---------------------|--------------------------------------|-----------------------|
| 后缀绕过          | `filename="test.asp;.jpg"`          | 文件类型校验缺陷       |
| Content-Disposition | `content-Disposition: form-data`    | 头解析大小写敏感性     |
| 魔术字节          | `GIF89a;<?php...`                   | 内容检测绕过          |
| 协议走私          | `Transfer-Encoding: chunked`        | WAF协议解析差异       |

## 作者信息
- **开发者**: T3nk0

## 免责声明
本工具仅限授权测试使用，禁止用于非法用途。使用者需遵守当地法律法规，开发者不承担任何滥用责任。
