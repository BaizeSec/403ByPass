# 403ByPass

**403绕过-BurpSuite插件 by 白泽Sec-ahui**

联系方式：aaaahuia@163.com

#### 工具简述：

基于常见的框架漏洞或IP伪造尝试绕过网页403限制

#### 使用方法：

`BurpSuite -> Extender -> Extensions -> Add -> Extension Type: Java -> Select file: 403ByPass_BaiZeSEC-1.0.jar -> Next till Finish`

#### 测试代码：

```php
<?php
if($_SERVER['HTTP_X_FORWARDED_FOR']=="127.0.0.1"){
	http_response_code(200);
	print("200 success");
}else{
	http_response_code(403);
	print("403 error");
}
```

