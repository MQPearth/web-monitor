# web-monitor

#### 通过以下三个指标判断目标网站是否正常

1. 是否能在指定时间内正常建立连接以及返回内容

2. HTTP Code 是否为200

3. 网站响应内容不包含指定的字符

若出现异常会通过阿里云短信进行通知

配置如下

```json
{
  //阿里短信配置
  "EndPoint": "http://dysmsapi.aliyuncs.com",
  //阿里短信配置
  "AccessKeyId": "*******",
  //阿里短信配置
  "AccessKeySecret": "*******",
  //阿里短信配置
  "SignName": "*******",
  //阿里短信配置
  "TemplateCode": "*******",
  //阿里短信配置
  "RegionId": "cn-shenzhen",
  //通知目标
  "PhoneNumbers": "*******",
  //关键字
  "HackedWords": [
    "ransom",
    "money"
  ],
  //连接超时时间 示例: 300ms
  "ConnectionTimeout": 300000,
  //内容读取时间 示例: 300ms
  "ReadTimeout": 300000
}
```

Run

```
./web-monitor -u http://localhost
```