# F5 Big-IP Cookie内网IP信息泄漏
## 简介
> BIG-IP是对负载均衡的实现，主要通过Virtual Server、iRules、Pool、Node、Monitor和Persistent（会话保持）实现。BIGip在实现会话保持机制时会在用户首次发起请求时，会为用户设置一个cookie，即服务端会添加set-cookie响应头头（比如：Set-Cookie: BIGipServerapp-enterprise-ebank-pool=2588125376.31523.0000）。后续的请求会判断并使用这个cookie值，服务端解码该cookie并使用服务器。

**漏洞危害比较低，危害主要体现在可以为内网渗透提供必要的信息，如IP地址段信息等。**

## 漏洞原理

```
F5中的cookies格式如下：
BIGipServer <pool name> = <编码服务器IP>.<编码服务器端口> .0000
从中我们可以得知一下信息：
BIGipServer - 我们现在知道服务器在F5 BigIP设备后面。
<pool name> - F5上配置的池名称。
<编码服务器IP> - 进行编码的服务器的真实IP。
<编码服务器端口> - 进行编码的服务器的真实端口。
```
下面我们来还原一下这个算法：
以这个为例：`BIGipServerapp-enterprise-ebank-pool=2588125376.31523.0000`
拿出值：2588125376
第一步：将该10进制值转换为16进制(得到一个8位的值，如果不够8位，前面补0)
```
9a43a8c0
```

第二步：将这个8位的值分为四段
```
9a 43 a8 c0
```

第三步：dao'zhi顺序将每段数字分别转换成10进制，分别得到4个数字
```
c0 → 192
a8 → 168
43 → 67
9a → 154
```

第四步：得到服务器真实内网ip：192.168.67.154

```python
import struct
import sys

def decode(cookie_value):
     (host, port, end) = cookie_value.split('.')
     (a, b, c, d) = [ord(i) for i in struct.pack("<I", int(host))]
     p = [ord(i) for i in struct.pack("<I", int(port))]
     port = p[0]*256 + p[1]
     print "%s.%s.%s.%s:%s" % (a,b,c,d,port)
if len(sys.argv) != 3:
     print "Usage: %s input_type encoded_string" % sys.argv[0]
     print "-c cookie value"
     print "-f File Name containing cookie values on each linen"
     print "ex. %s -c 487098378.24095.0000" % sys.argv[0]
     print "ex. %s -f file.txt" % sys.argv[0]
     exit(1)
if sys.argv[1] == "-c":
     cookie_text = sys.argv[2]
     decode(cookie_text)
if sys.argv[1] == "-f":
     file_name = sys.argv[2]
     with open(file_name,"r") as f:
          for x in f:
               x = x.rstrip()
               if not x: continue
               decode(x)
```

## 利用
rabid工具可以解BigIP的cookie，以此获取内网ip或者真实ip地址。这款工具名叫rabid，是ruby语言编写，支持4种cookie格式。
github地址：https://github.com/Orange-Cyberdefense/rabid

```http
GET http://htwxclaim.pc.ehuatai.com/web-console/ HTTP/1.1
Host: htwxclaim.pc.ehuatai.com
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://htwxclaim.pc.ehuatai.com/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: BIGipServershangxianyidong=1443234058.36895.0000
Connection: close
```

![](media/16208263887101/16208264788337.jpg)


```
Cookie: BIGipServershangxianyidong=1443234058.36895.0000
```
利用工具`rabid`进行F5 BigIP解码，可以获取真实内网IP地址，如下：
![](media/16208263887101/16208264238123.jpg)

## 修复方案
在F5设备中，设置cookie加密方法。
![解决1](media/16218346928127/%E8%A7%A3%E5%86%B31.png)

在创建新HTTP配置文件部分中设置
![解决2](media/16218346928127/%E8%A7%A3%E5%86%B32.png)

返回到服务器中应用创建的自定义HTTP配置文件
![解决3](media/16218346928127/%E8%A7%A3%E5%86%B33.png)

做好以上设置后，再来查看数据包中的cookie已使用AES加密，并使用base64进行了编码。
![解决4](media/16218346928127/%E8%A7%A3%E5%86%B34.png)

