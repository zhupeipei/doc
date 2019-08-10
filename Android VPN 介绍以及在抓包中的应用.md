# Android VPN 介绍以及在抓包中的应用
## $ 1 VPN 介绍和VPN协议类型

## $ 1.1 VPN 介绍
VPN的目的是能够在外网(不同网段)访问到内网资源。解决方法就是在内网中架设一台VPN服务器。用户在当地连上互联网后，通过互联网连接VPN服务器，然后通过VPN服务器进入企业内网。为了保证数据安全，VPN服务器和客户机之间的通讯数据都进行了加密处理。有了数据加密，就可以认为数据是在一条专用的数据链路上进行安全传输，就如同专门架设了一个专用网络一样，但实际上VPN使用的是互联网上的公用链路，因此VPN称为虚拟专用网络，其实质上就是利用加密技术在公网上封装出一个数据通讯隧道。有了VPN技术，用户无论是在外地出差还是在家中办公，只要能上互联网就能利用VPN访问内网资源，这就是VPN在企业中应用得如此广泛的原因。

![](images/vpn&#32;intro.png)

假设要访问谷歌，那么客户端发出的数据包首先通过协议栈处理封装成IP包，其源地址是虚拟网卡的地址，例如：192.168.0.2，而目标地址是谷歌的IP。

原始IP包交给虚拟网卡发送时，PPTP网卡驱动会按PPP协议对这个IP包整体加密封装作为新的payload，用一层新的IP头封装这个payload发送出去，这个新IP头的目标地址是vpn server，源地址是客户端的外网IP。

vpn server的协议栈会剥离掉新IP头，将内部PPP协议的payload交给pptpd进程处理，pptpd进程会按PPP协议解包得到原始的IP包，我们知道这个IP包的源地址是192.168.0.2，目标地址google。因此，pptpd进程需要做的是将这个IP包的源IP地址改为vps的地址，然后将IP包发给谷歌，从而和谷歌进行数据交换。最终，pptpd理所应当将谷歌的应答IP包的目标IP地址换成192.168.0.2，然后经过PPP协议封装并添加新的IP头后发回给客户端既可。

不过要注意在pptpd的实现里，这个源地址修改是通过iptables实现的，也就是添加通过iptables添加一个NAT规则，实现来源地址的映射转换，这个在你配置pptp的过程中就会看到。

## $ 1.2 VPN协议类型和PPTP原理
VPN的隧道协议主要有三种，PPTP、L2TP和IPSec，其中PPTP和L2TP协议工作在OSI模型的第二层，又称为二层隧道协议；IPSec是第三层隧道协议。

常用的vpn方式有PPTP、L2TP/IPSec VPN、OpenVPN，三者的对比如下：

![](images/Android&#32;vpn/vpn&#32;category.png)

PPTP包结构如下： 
![](images/Android&#32;vpn/pptp&#32;packet.png)


PPTP 封包过程如下：

<p align="center">
    <img src="images/Android&#32;vpn/pptp&#32;packet&#32;yuanli.png" width="80%" />
</p>
<!-- ![](images/Android&#32;vpn/pptp&#32;packet&#32;yuanli.png) -->

    1、  应用层数据封装成IP数据包

    2、  将IP数据包发送到VPN的虚拟接口

    3、  VPN的虚拟接口将IP数据包压缩和加密，并增加PPP头

    4、  VPN的虚拟接口将PPP帧发送给PPTP协议驱动程序

    5、  PPTP协议驱动程序在PPP帧外添加GRE报头

    6、  PPTP协议驱动程序将GRE报头提交给TCP/IP协议驱动程序

    7、  TCP/IP协议驱动程序为GRE驱动添加IP头部

    8、  为IP数据包进行数据链路层封装后通过物理网卡发送出去

PPTP 解包过程如下：

<p align="center">
    <img src="images/Android&#32;vpn/pptp&#32;unpacket&#32;yuanli.png" width="80%" />
</p>

    1、物理thernet帧

    2、剥掉Ethernet帧后交给TCP/IP协议驱动程序

    3、TCP/IP协议解析剥掉IP头部

    4、IP协议解析剥掉GRE头部

    5、将PPP帧发送给VPN虚拟网卡

    6、VPN虚拟网卡剥掉PPP头并对PPP有效负载进行解密或者解压缩

    7、解密或者解压缩完成后将数据提交给上层应用

    8、上层应用对数据进行处理

## $ 2 Android VPN

### $ 2.1 原理

<p align="center">
    <img src="images/Android&#32;vpn/android&#32;vpn.png" width="80%" />
</p>

<!-- ![](images/Android&#32;vpn/android&#32;vpn.png) -->


    1、 应用程序使用socket，将相应的数据包发送到真实的网络设备上。一般移动设备只有无线网卡，因此是发送到真实的WiFi设备上；
    
    2、 Android系统通过iptables，使用NAT，将所有的数据包转发到TUN虚拟网络设备上去，端口是tun0；
    
    3、 VPN程序通过打开/dev/tun设备，并读取该设备上的数据，可以获得所有转发到TUN虚拟网络设备上的IP包。
        因为设备上的所有IP包都会被NAT转成原地址是tun0端口发送的，
        所以也就是说你的VPN程序可以获得进出该设备的几乎所有的数据（也有例外，不是全部，比如回环数据就无法获得）；
    
    4、 VPN数据可以做一些处理，然后将处理过后的数据包，通过真实的网络设备发送出去。
        为了防止发送的数据包再被转到TUN虚拟网络设备上，VPN程序所使用的socket必须先被明确绑定到真实的网络设备上去。

### $ 2.2 VPNService

3个比较重要的方法
prepare / establish / protect

1. prepare函数的目的，主要是用来检查当前系统中是不是已经存在一个VPN连接了，如果有了的话，是不是就是本程序创建的。
   如果当前系统中没有VPN连接，或者存在的VPN连接不是本程序建立的，则VpnService.prepare函数会返回一个intent。这个intent就是用来触发确认对话框的，程序会接着调用startActivityForResult将对话框弹出来等用户确认。如果用户确认了，则会关闭前面已经建立的VPN连接，并重置虚拟端口。该对话框返回的时候，会调用onActivityResult函数，并告之用户的选择。
   如果当前系统中有VPN连接，并且这个连接就是本程序建立的，则函数会返回null，就不需要用户再确认了。因为用户在本程序第一次建立VPN连接的时候已经确认过了，就不要再重复确认了，直接手动调用onActivityResult函数就行了。
2. establish函数，如果一切正常的话，tun0虚拟网络接口就建立完成了。并且，同时还会通过iptables命令，修改NAT表，将所有数据转发到tun0接口上。
   这之后，就可以通过读写VpnService.Builder返回的ParcelFileDescriptor实例来获得设备上所有向外发送的IP数据包和返回处理过后的IP数据包到TCP/IP协议栈：

```
// Packets to be sent are queued in this input stream.
FileInputStream in = new FileInputStream(interface.getFileDescriptor());
 
// Packets received need to be written to this output stream.
FileOutputStream out = new FileOutputStream(interface.getFileDescriptor());
 
// Allocate the buffer for a single packet.
ByteBuffer packet = ByteBuffer.allocate(32767);
...
// Read packets sending to this interface
int length = in.read(packet.array());
...
// Write response packets back
out.write(packet.array(), 0, length);
```
3. protect(my_socket);
将这个socket和真实的网络接口进行绑定，保证通过这个socket发送出去的数据包一定是通过真实的网络接口发送出去的，不会被转发到虚拟的tun0接口上去。防止造成死循环。

### $ 2.3 地址转换

<p align="center">
    <img src="images/Android&#32;vpn/nat.png" width="80%" />
</p>

<!-- ![](images/Android&#32;vpn/nat.png) -->

最后，简单总结一下：

1）VPN连接对于应用程序来说是完全透明的，应用程序完全感知不到VPN的存在，也不需要为支持VPN做任何更改；

2）并不需要获得Android设备的root权限就可以建立VPN连接。你所需要的只是在你应用程序内的AndroidManifest.xml文件中申明需要一个叫做“android.permission.BIND_VPN_SERVICE”的特殊权限；

3）在正式建立VPN链接之前，Android系统会弹出一个对话框，需要用户明确的同意；

4）一旦建立起了VPN连接，Android设备上所有发送出去的IP包，都会被转发到虚拟网卡的网络接口上去（主要是通过给不同的套接字打fwmark标签和iproute2策略路由来实现的）；

5）VPN程序可以通过读取这个接口上的数据，来获得所有设备上发送出去的IP包；同时，可以通过写入数据到这个接口上，将任何IP数据包插入系统的TCP/IP协议栈，最终送给接收的应用程序；

6）Android系统中同一时间只允许建立一条VPN链接。如果有程序想建立新的VPN链接，在获得用户同意后，前面已有的VPN链接会被中断；

7）这个框架虽然叫做VpnService，但其实只是让程序可以获得设备上的所有IP数据包。通过前面的简单分析，大家应该已经感觉到了，这个所谓的VPN服务，的确可以方便的用来在Android设备上建立和远端服务器之间的VPN连接，但其实它也可以被用来干很多有趣的事情，比如可以用来做防火墙，也可以用来抓设备上的所有IP包。
## $ 3 抓包原理
利用VPN 可以获取大部分几乎所有的 IP 数据包。

### $ 3.1 IP包结构和SSL握手过程
本文只考虑http和https的请求，由于基于 TCP 协议，UDP 协议的数据内容暂不考虑。
#### $ 3.1.1 IP包结构
Request 和 Response 的数据位于 TCP 的用户数据中。且其中 Request Body 和 Response Body 的内容可能会进行 Gzip 压缩。对于http而言，Gzip 解压缩后几乎就是明文数据。
![](images/Android&#32;vpn/ip&#32;packet.png)

#### $ 3.1.2 SSL握手过程

<p align="center">
    <img src="images/Android&#32;vpn/https&#32;tls.jpg" width="100%" />
</p>
<!-- ![](images/Android&#32;vpn/https&#32;tls.jpg) -->

1. Client Hello
   客户端向服务端发起请求，向服务端提供：
   支持的协议版本（如：TLS 1.2）
   随机数Random_C，第一个随机数，后续生成“会话密钥”会用到
   支持的加密方法列表
   支持的压缩方法，等等

![](images/Android&#32;vpn/client&#32;hello.jpeg)
2. Server Hello
   服务端向客户端发起响应，响应信息包含：
   确认使用的加密通信协议版本（如：TLS 1.2）
   随机数 Random_S，第二个随机数，后续生成“会话密钥”会用到
   确认使用的加密算法，（如 RSA 公钥加密）
   确认使用的压缩方法
![](images/Android&#32;vpn/server&#32;hello.jpeg)

3. Certificate + Server Key Exchange + Server Hello Done
   Certificate: 返回服务器证书，该证书中含有一个公钥，用于身份验证和密钥协商

   Server Key Exchange: 当服务器证书中信息不足，不能让 Client 完成 premaster 的密钥交换时，会发送该消息
   RSA的情况下：
   公钥密码参数
   N(modulus)
   E(exponent)
   散列值
   Diffie-Hellman 密钥交换的情况下：
   密钥交换的参数
   dh_p Diffie-Hellman密钥协商计算的大质数模数
   dh_g Diffie-Hellman 的生成元
   dh_Ys 服务器的Diffie-Hellman公钥 (g^X mod p)
   散列值
   
   Server Hello Done: 通知客户端 server_hello 信息发送结束。
![](images/Android&#32;vpn/sever&#32;hello&#32;done.jpeg)

4. Certificate Request
   如果需要双向验证时，服务端会向客户端请求证书

5. 客户端验证证书
   客户端收到服务器证书后，进行验证，如果证书不是可信机构颁发的，或者域名不一致，或者证书已经过期，那么客户端会进行警告；如果证书没问题，那么继续进行通信。

6. Client Key Exchange + Change Cipher Spec + Encrypted Handshake Message
   Client Key Exchange：证书验证通过后，客户端会生成整个握手过程中的第三个随机数，并且从证书中取出公钥，利用公钥以及双方实现商定的加密算法进行加密，生成Pre-master key，然后发送给服务器。
   服务器收到 Pre-master key后，利用私钥解密出第三个随机数，此时，客户端和服务端同时拥有了三个随机数：Random_C, Random_S,Pre-master key,两端同时利用这三个随机数以及事先商定好的加密算法进行对称加密，生成最终的“会话密钥”，后续的通信都用该密钥进行加密。这一个过程中，由于第三个随机数是通过非对称加密进行加密的，因此不容易泄漏，也就“会话密钥”是安全的，后续的通信也就是安全的。
   Change Cipher Spec：客户端通知服务端，随后的信息都是用商定好的加密算法和“会话密钥”加密发送。
   Encrypted Handshake Message：客户端握手结束通知，这一项同时也是前面发送的所有内容的hash值，用来供服务器校验。

![](images/Android&#32;vpn/change&#32;cipher&#32;spec.jpeg)

7. Certificate
   客户端发送证书给服务器

8. Change Cipher Spec + Encrypted Handshake Message
   Change Cipher Spec：服务端通知客户端，随后的信息都是用商定好的加密算法和“会话密钥”加密发送。
   Encrypted Handshake Message：服务器握手结束通知，这一项同时也是前面发送的所有内容的hash值，用来供客户端校验。

![](images/Android&#32;vpn/handshake.jpeg)

9. Application Data
    至此，整个握手过程就完成了，客户端和服务端进入加密通信。

![](images/Android&#32;vpn/http&#32;over&#32;tls.jpeg)

### $ 3.2 中间人攻击 MITM 原理

几乎所有网络数据的抓包都是采用中间人的方式（MITM），包括大家常用的Fiddler、Charles等知名抓包工具。Android VPN因为可以获取设备发出的所有网络数据，因而可以进行抓包。
<p align="center">
    <img src="images/Android&#32;vpn/mitm.png" width="100%" />
</p>
<!-- ![](images/Android&#32;vpn/mitm.png) -->

从上面这个原理图，可以看出抓包的核心问题主要是两个：

MITM Server如何伪装成真正的Server；
MITM Client如何伪装成真正的Client。

第一个问题，MITM Server要成为真正的Server，必须能够给指定域名签发公钥证书，且公钥证书能够通过系统的安全校验。比如Client发送了一条https://www.baidu.com/的网络请求，MITM Server要伪装成百度的Server，必须持有www.baidu.com域名的公钥证书并发给Client，同时还要有与公钥相匹配的私钥。
MITM Server的处理方式是从第一个SSL/TLS握手包Client Hello中提取出域名 www.baidu.com，利用应用内置的CA证书创建www.baidu.com域名的公钥证书和私钥。创建的公钥证书在SSL/TLS握手的过程中发给Client，Client收到公钥证书后会由系统会对此证书进行校验，判断是否是百度公司持有的证书，但很明显这个证书是抓包工具伪造的。为了能够让系统校验公钥证书时认为证书是真实有效的，我们需要将抓包应用内置的CA证书手动安装到系统中，作为真正的证书发行商（CA），即洗白。这就是为什么，HTTPS抓包一定要先安装CA证书。
第二个问题，MITM Client伪装成Client。由于服务器并不会校验Client（绝大部分情况），所以这个问题一般不会存在。比如Server一般不会关心Client到底是Chrome浏览器还是IE浏览器，是Android App还是iOS App。当然，Server也是可以校验Client的，由于比较复杂，本文暂不做分析。

### $ 3.3 OkHttp SSL 握手

```
Request request = new Request.Builder().get().url("https://www.baidu.com").build();

OkHttpClient.Builder builder = new OkHttpClient.Builder();

OkHttpClient client = builder.build();

client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
            }
            @Override
    public void onResponse(Call call, Response response) throws IOException {
    }
});
```
```
private SSLSocketFactory getSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
    SSLContext context = SSLContext.getInstance("TLS");
    TrustManager[] trustManagers = {new MyX509TrustManager()};
    context.init(null, trustManagers, new SecureRandom());
    return context.getSocketFactory();
}
```

```
private class MyX509TrustManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null) {
            throw new CertificateException("checkServerTrusted: X509Certificate array is null");
        }
        if (chain.length < 1) {
            throw new CertificateException("checkServerTrusted: X509Certificate is empty");
        }
        if (!(null != authType && authType.equals("ECDHE_RSA"))) {
            throw new CertificateException("checkServerTrusted: AuthType is not ECDHE_RSA");
        }

        //检查所有证书
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance("X509");
            factory.init((KeyStore) null);
            for (TrustManager trustManager : factory.getTrustManagers()) {
                ((X509TrustManager) trustManager).checkServerTrusted(chain, authType);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        //获取本地证书中的信息
        String clientEncoded = "";
        String clientSubject = "";
        String clientIssUser = "";
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            InputStream inputStream = getAssets().open("baidu.cer");
            X509Certificate clientCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            clientEncoded = new BigInteger(1, clientCertificate.getPublicKey().getEncoded()).toString(16);
            clientSubject = clientCertificate.getSubjectDN().getName();
            clientIssUser = clientCertificate.getIssuerDN().getName();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //获取网络中的证书信息
        X509Certificate certificate = chain[0];
        PublicKey publicKey = certificate.getPublicKey();
        String serverEncoded = new BigInteger(1, publicKey.getEncoded()).toString(16);

        if (!clientEncoded.equals(serverEncoded)) {
            throw new CertificateException("server's PublicKey is not equals to client's PublicKey");
        }
        String subject = certificate.getSubjectDN().getName();
        if (!clientSubject.equals(subject)) {
            throw new CertificateException("server's subject is not equals to client's subject");
        }
        String issuser = certificate.getIssuerDN().getName();
        if (!clientIssUser.equals(issuser)) {
            throw new CertificateException("server's issuser is not equals to client's issuser");
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
```

### 3.4 https证书洗白
#### 一、 如果用户对服务端没有校验证书，那么MITM设置的证书都可以进行洗白，这种情况下的https其实就是披着狼皮的羊。


#### 二、 如果APP对服务端仅通过校验CA证书，那么MITM服务端证书可以洗白的路径有以下4种方式：
1. AndroidManifest中配置networkSecurityConfig
```
<?xml version="1.0" encoding="utf-8"?>
<manifest ... >
    <application android:networkSecurityConfig="@xml/network_security_config"
                    ... >
        ...
    </application>
</manifest>
```
```
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

2. 调低targetSdkVersion < 24
如果想抓一个App的包，可以找个历史版本，只需要其targetSdkVersion < 24即可。然而，随着GooglePlay开始限制targetSdkVersion，现在要求其必须>=26，2019年8月1日后必须>=28，国内应用市场也开始逐步响应这种限制。绝大多数App的targetSdkVersion都将大于24了，也就意味着抓HTTPS的包越来越难操作了。
3. 平行空间抓包
如果我们希望抓targetSdkVersion >= 24的应用的包，那又该怎么办呢？我们可以使用平行空间或者VirtualApp来曲线救国。平行空间和VirtualApp这种多开应用可以作为宿主系统来运行其它应用，如果平行空间和VirtualApp的targetSdkVersion < 24，那么问题也就解决了。
在此，我推荐使用平行空间，相比部分开源的VirtualApp，平行空间运行得更加稳定。但必须注意平行空间的版本4.0.8625以下才是targetSdkVersion < 24，别安装错了。当然，HttpCanary的设置中是可以直接安装平行空间的。
4. 安装到系统CA证书目录
对于Root的机器，这是最完美最佳的解决方案。如果把CA证书安装到系统CA证书目录中，那这个假CA证书就是真正洗白了，不是真的也是真的了。

#### 如果APP内置了服务端证书，在HTTPS请求时，Server端发给客户端的公钥证书必须与Client端内置的公钥证书一致，请求才会成功。
这种情况下要么传入真正的服务端证书；要么通过hook破解证书固定，具体可以参考 [JustTrustMe](https://github.com/Fuzion24/JustTrustMe)

### 3.5 抓包流程图

![](images/Android&#32;vpn/vpn&#32;capture&#32;packet.jpg)

## $ 4 附录
### $ 4.1 参考文章


### $ 4.2 tcp/ip

![](images/Android&#32;vpn/tcp&#32;ip.gif)