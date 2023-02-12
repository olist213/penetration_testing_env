搭建的基础环境分成三类。

1、给了源代码，需要自己动手搭建的环境，如dvwa等。

2、docker类的环境，如vulfocus，vulhub等环境已经集成了。

3、vmware虚拟机靶场，这种靶场多涉及后渗透阶段，如内网渗透、域渗透。

工艺善其事，必先利其器。
- ~~windows~~
- phpstudy（https://www.xp.cn/download.html）

![](https://s2.loli.net/2022/02/23/Qovu91hlxqAJXWk.png)

# 第一类 源代码类

## php环境

- dvwa
  - https://dvwa.co.uk/

- PHP代码审计分段讲解
  - [php_bugs](https://github.com/bowu678/php_bugs)

Pikachu是一个带有漏洞的Web应用系统，在这里包含了常见的web安全漏洞。
- [pikachu](https://github.com/zhuifengshaonianhanlu/pikachu)

文件上传靶场
- [upload-labs](https://github.com/c0ny1/upload-labs/releases/tag/0.1)

web漏洞靶场
- [webug](https://github.com/wangai3176/webug4.0)

sqli注入靶场
- [sqli-labs](https://github.com/skyblueee/sqli-labs-php7)

xxe漏洞靶场

- [xxe-lab](https://github.com/c0ny1/xxe-lab)

burpsuite的[官网](https://portswigger.net/web-security/all-labs)也提供了很多web方面的漏洞，都是主流漏洞。

php反序列化靶场

https://github.com/fine-1/php-SER-libs

## asp/x环境

asp的环境需要设置iis环境，也可以使用超级小旋风AspWebServer漏洞环境。asp搭配的数据库是access、sqlserver，如果需要用到数据库也需要安装上。

https://github.com/Larryxi/MSSQL-SQLi-Labs

## jsp环境

参考：

https://github.com/tangxiaofeng7/SecExample

https://github.com/l4yn3/micro_service_seclab

RASP测试靶场
https://github.com/javaweb-rasp/javaweb-vuln

 Java Security，安全编码和代码审计
 https://github.com/j3ers3/Hello-Java-Sec

 ![image](https://user-images.githubusercontent.com/46209842/166251371-1b491599-a0d5-47f3-bb2a-91d7bcf44d2f.png)
 
 逻辑漏洞靶场
 
 https://github.com/yingshang/ywljsec
 
 逻辑漏洞靶场环境安装：
 
 ```
 #安装django和faker
 python -m pip install Django
 pip3 install faker
 
 #初始化数据库
 先运行python manage.py runserver，然后浏览器访问http://127.0.0.1:8000/init_data接口初始化数据库，后面访问http://127.0.0.1:8000/即可。
 ```

# 第二类 docker类

使用docker快速搭建各大漏洞靶场，目前可以一键搭建17个靶场。

- [vulstudy](https://github.com/c0ny1/vulstudy)

![](https://s2.loli.net/2022/02/23/J7P2UL6VrfcGutZ.png)

上述平台直接用docker即可一键搭建漏洞环境。

Vulfocus 是一个漏洞集成平台，将漏洞环境 docker 镜像，放入即可使用，开箱即用，[vulhub](https://github.com/vulhub/vulhub)的一些漏洞环境vulfocus中也有，就不一一说明了。

- [vulfocus](https://fofapro.github.io/vulfocus/#/)

```bash
docker pull vulfocus/vulfocus:latest

docker run -d -p 80:80 -v /var/run/docker.sock:/var/run/docker.sock -e VUL_IP=x.x.x.x(本机ip) vulfocus/vulfocus

账号密码：admin/admin
```

- php反序列化docker环境

https://github.com/mcc0624/php_ser_Class

```
docker pull mcc0624/ser:1.8
docker run -p 8002:80 -d mcc0624/ser:1.8
```

- struts2漏洞环境

https://github.com/Ranwu0/Struts2-Tools

# 第三类 虚拟机

虚拟机的漏洞环境，先介绍几个在线的网站，这些在线的靶场不需要下载。

- [hackthebox](https://app.hackthebox.com/login)
- [tryhackme](https://tryhackme.com/)
- [attackdefense](https://attackdefense.com/)

上面的三个网站，质量都挺高的。

虚拟机类的靶场，通常需要自己下载[vmware](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)或[virtual box](https://www.virtualbox.org/)d的ova格式虚拟镜像，然后导入到虚拟机中运行。

[vulnhub](https://www.vulnhub.com/)z中有很多虚拟机靶场，目标都是获取flag。

注：在导入虚拟机后，首先需要获取靶机的ip地址，通常靶机都是dhcp获取ip，那么你就需要用nmap扫描你当前网段，如果网段内ip太多，就不容易识别，况且如果用vmware时，会有获取不到ip的情况。建议练习vulnhub的靶场时，用virtualbox虚拟机，如果是linux，导入后，进入修改密码的模式（开机按e），修改密码，先获取ip。

除了vulnhub的靶场，还有一些团队搭建的靶场环境，如红日安全的[ATT&CK实战系列](http://vulnstack.qiyuanxuetang.net/vuln/)。

![](https://s2.loli.net/2022/02/23/H2NQuYJyzlErvbw.png)

[windows/linux本地特权提升实验](https://github.com/sagishahar/lpeworkshop)，包含的内容都是提权相关的知识点。

![](https://s2.loli.net/2022/02/23/rMfBwJo3vOVuAnm.png)

- vulntarget靶场系列

https://github.com/crow821/vulntarget

大概想到的就这些，如果还有其他的就慢慢更新，还有一些asp/x、jsp/x的环境后期慢慢整理。

# 其他

seed-labs：网络攻防课程中涉及的seed-labs实验代码和报告

https://github.com/Seanxz401/seed-labs



