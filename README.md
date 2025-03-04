
## 0x01 靶场类别

搭建的基础环境一般可分成三类。

1、给了源代码，需要自己动手搭建的环境，有源码也可以通过docker搭建环境，通过Dockerfile去构建，上传至dockerhub可重复使用，java和php的构建比较简单，而asp/x用docker构建就比较少了，除了docker之外，php也可以用phpstudy这种集成环境搭建。

2、docker类的环境，这里说的docker类的环境指的是那种集成类的有CVE编号的环境，如vulfocus，vulhub等环境，前人已经构建好，我们只要docker pull下来即可。

3、vmware虚拟机靶场，这种靶场多涉及后渗透阶段，如内网渗透、域渗透等，如[GOAD](https://0x7e.cn/records/goad-game-of-active-directory)靶场。

## 0x02 工具

工艺善其事，必先利其器。

- windows(docker desktop),mac(orb)
- phpstudy（https://www.xp.cn/download.html）
- ctfd
- gzctf

如果自己想整合自己搭建的环境或公司内部给同事练习，可以搭建一个ctf平台，如ctfd和gzctf。ctfd结合[whale](https://github.com/frankli0324/ctfd-whale)插件可以实现动态flag，添加docker类环境。

![image](https://github.com/user-attachments/assets/550c8fe8-da27-4778-b96d-cba74439bda9)

ctfd添加靶场可以去[dockerhub](https://hub.docker.com/)上找，如[vulfocus](https://hub.docker.com/u/vulfocus)的靶场环境。

![image](https://github.com/user-attachments/assets/fc379984-b8ca-43e8-8f9c-2b812dbb150c)

## 0x03 php环境

- dvwa
  - https://dvwa.co.uk/

- PHP代码审计分段讲解
  - [php_bugs](https://github.com/bowu678/php_bugs)

- Pikachu是一个带有漏洞的Web应用系统，在这里包含了常见的web安全漏洞。
  - [pikachu](https://github.com/zhuifengshaonianhanlu/pikachu)，可docker部署
  - 在线pikachu类靶场：[渊龙Sec团队官方漏洞靶场](http://ctf.aabyss.cn/index.php)

- 文件上传靶场
  - [upload-labs](https://github.com/c0ny1/upload-labs/releases/tag/0.1)

- web漏洞靶场
  - ~~[webug](https://github.com/wangai3176/webug4.0)~~
  - docker搭建：`docker pull area39/webug`
  
- sqli注入靶场
  - [sqli-labs](https://github.com/skyblueee/sqli-labs-php7)

- xxe漏洞靶场

  - [xxe-lab](https://github.com/c0ny1/xxe-lab)
  - [xxe08](https://github.com/mcc0624/XXE)

- burpsuite的[官网](https://portswigger.net/web-security/all-labs)也提供了很多web方面的漏洞，都是主流漏洞。

- php反序列化靶场

  - https://github.com/fine-1/php-SER-libs
  - https://github.com/ProbiusOfficial/PHPSerialize-labs
  - https://github.com/mcc0624/php_ser_Class

- SSRF漏洞靶场
  - https://github.com/sqlsec/ssrf-vuls

- 电气鼠靶场系统
  - https://github.com/linjiananallnt/ElectricRat
 
- PHP命令执行漏洞的学习靶场
  - https://github.com/mcc0624/php_cmd/
 
- php反序列化docker环境
  - https://github.com/mcc0624/php_ser_Class

docker搭建

```
docker pull mcc0624/ser:1.8
docker run -p 8002:80 -d mcc0624/ser:1.8
```

## 0x04 asp/x环境

asp的环境需要设置iis环境，也可以使用超级小旋风AspWebServer漏洞环境。asp搭配的数据库是access、sqlserver，如果需要用到数据库也需要安装上。

https://github.com/Larryxi/MSSQL-SQLi-Labs

## 0x05 jsp环境

- [JAVA 漏洞靶场 (Vulnerability Environment For Java)](https://github.com/tangxiaofeng7/SecExample)
- [Java漏洞靶场](https://github.com/l4yn3/micro_service_seclab)
- [RASP测试靶场](https://github.com/javaweb-rasp/javaweb-vuln)
- [JavaSecLab 一款综合Java漏洞平台](https://github.com/whgojp/JavaSecLab)
- [Java Security，安全编码和代码审计](https://github.com/j3ers3/Hello-Java-Sec)
  - docker版：`docker pull liangchenga/javasec:1.5`

 ![image](https://user-images.githubusercontent.com/46209842/166251371-1b491599-a0d5-47f3-bb2a-91d7bcf44d2f.png)

- [weblogic靶场](https://github.com/QAX-A-Team/WeblogicEnvironment)
- [struts2漏洞环境](https://github.com/Ranwu0/Struts2-Tools)
- [FastJson全版本Docker漏洞环境](https://github.com/lemono0/FastJsonParty)

 ## 0x06 逻辑漏洞靶场

https://github.com/yingshang/ywljsec

 逻辑漏洞靶场环境安装：

 ```
 #安装django和faker
 python -m pip install Django
 pip3 install faker
 
 #初始化数据库
 先运行python manage.py runserver，然后浏览器访问http://127.0.0.1:8000/init_data接口初始化数据库，后面访问http://127.0.0.1:8000/即可。
 ```

 做了个docker环境:

 ```
 docker pull liangchenga/ljldsec:latest
 ```

## 0x07 docker环境

使用docker快速搭建各大漏洞靶场，目前可以一键搭建17个靶场。

- [vulstudy](https://github.com/c0ny1/vulstudy)

![](https://s2.loli.net/2022/02/23/J7P2UL6VrfcGutZ.png)

上述平台直接用docker即可一键搭建漏洞环境。

Vulfocus 是一个漏洞集成平台，将漏洞环境 docker 镜像，放入即可使用，开箱即用，[vulhub](https://github.com/vulhub/vulhub)的一些漏洞环境vulfocus中也有，就不一一说明了。

- [vulfocus](https://fofapro.github.io/vulfocus/#/)

```bash
docker pull vulfocus/vulfocus:latest
docker run -d -p 80:80 -v /var/run/docker.sock:/var/run/docker.sock -e VUL_IP=x.x.x.x(本机ip) vulfocus/vulfocus
#账号密码：admin/admin
```

- iwebsec
  - docker pull iwebsec/iwebsec

## 0x08 虚拟机

虚拟机的漏洞环境，先介绍几个在线的网站，这些在线的靶场不需要下载。

- [hackthebox](https://app.hackthebox.com/login)
- [tryhackme](https://tryhackme.com/)
- [attackdefense](https://attackdefense.com/)
- [春秋云镜](https://yunjing.ichunqiu.com/)
- [pentesterlab](https://pentesterlab.com/)

上面的这些网站，质量都挺高的，还有一些可自己尝试下，[Websites/Platforms to learn to hack](https://twitter.com/nandanlohitaksh/status/1580154447808065536)。

虚拟机类的靶场，通常需要自己下载[vmware](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)或[virtual box](https://www.virtualbox.org/)d的ova格式虚拟镜像，然后导入到虚拟机中运行。

[vulnhub](https://www.vulnhub.com/)中有很多虚拟机靶场，目标都是获取flag。

注：在导入虚拟机后，首先需要获取靶机的ip地址，通常靶机都是dhcp获取ip，那么你就需要用nmap扫描你当前网段，如果网段内ip太多，就不容易识别，况且如果用vmware时，会有获取不到ip的情况。建议练习vulnhub的靶场时，用virtualbox虚拟机，如果是linux，导入后，进入修改密码的模式（开机按e），修改密码，先获取ip。

除了vulnhub的靶场，还有一些团队搭建的靶场环境，如:

- 红日安全的[ATT&CK实战系列](http://vulnstack.qiyuanxuetang.net/vuln/)。

![](https://s2.loli.net/2022/02/23/H2NQuYJyzlErvbw.png)

- [windows/linux本地特权提升实验](https://github.com/sagishahar/lpeworkshop)，包含的内容都是提权相关的知识点。

![](https://s2.loli.net/2022/02/23/rMfBwJo3vOVuAnm.png)

- vulntarget靶场系列

https://github.com/crow821/vulntarget

## 0x09 其他

[seed-labs[(https://github.com/Seanxz401/seed-labs)：网络攻防课程中涉及的seed-labs实验代码和报告

## 0x10 ctf在线靶场

- [buuoj](https://buuoj.cn/)
- [ctf.show](https://ctf.show/)
- [ctfhub](https://www.ctfhub.com/)
- [WgpSec ctf](https://ctf.wgpsec.org/)
- [316ctf](https://play.316ctf.com/)
- [tctf](http://ctf.tidesec.com/)
- [CTFd靶场搭建知识库](https://www.yuque.com/dat0u/ctfd/sm2tt0)
- [NSSCTF](https://www.nssctf.cn/)
- [ctftime](https://ctftime.org/)
- [bugku](https://ctf.bugku.com/)
- [picoctf](https://picoctf.org/)


