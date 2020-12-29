# 组件介绍
## 功能介绍
cert-toolkit用于证书生成。支持轻量级jar包接入。

支持如下方式：
*   根证书生成
*   证书请求生成
*   子证书生成   
*   证书文件的读写

## 基本概念
### 私钥、公钥、
在非对称加密领域，对数据的加解密、签名都依赖于密钥对。在密钥对中，公开的密钥叫公钥，只有自己知道的叫私钥。
非对称加密有许多体系，最著名的是RSA、DH、ECDSA。其中ECDSA是区块链领域采纳的密钥体系，也称为椭圆曲线体系，该体系中，私钥是一个某范围内的整数，公钥则是曲线上的一个点。

### 曲线
在椭圆曲线体系中，密钥生成依赖于曲线参数，一条曲线中合法的密钥对，在另一条曲线的环境中，就是非法密钥。最经典的曲线之一就是secp256k1，为多种主流区块链采纳；另一种曲线是国密曲线sm2p256v1，该曲线满足我国的密码学标准。

### 证书
证书用于确定实体身份和公钥的关系，上面定义了实体身份、公钥等信息，且证书会包含权威机构的数字签名作为背书。


# 部署说明

目前支持从源码进行部署。

### 1. 获取源码

通过git下载源码：

```
git clone https://github.com/WeBankBlockchain/Gov-Cert.git
```

进入目录：
```
cd Gov-Cert
cd cert-toolkit
```

### 2. 编译源码

方式一：如果服务器已安装Gradle
```
gradle build -x test
```

方式二：如果服务器未安装Gradle，使用gradlew编译
```
chmod +x ./gradlew && ./gradlew build -x test
```

### 3. 导入jar包

cert-toolkit编译之后在cert-toolkit目录下会生成dist文件夹，文件夹中包含cert-toolkit.jar。可以将cert-toolkit.jar导入到自己的项目中，例如libs目录下。然后进行依赖配置。gradle依赖配置如下，然后再对自己的项目进行编译。

```
repositories {
    mavenCentral()
    mavenLocal()
    maven {
        url "http://maven.aliyun.com/nexus/content/groups/public/"
    }
}

dependencies {
    compile fileTree(dir:'libs',include:['*.jar'])
}

```
### 4. 接口使用

cert-toolkit中包含若干类服务接口，如下，接口使用可以通过new对象然后调用

- CertService：证书的生成


```java

CertService certService =new CertService();

```


#### 4.1 CertService使用

CertService提供了三种功能接口：
- createRootCertificate：生成根证书，即自签名证书
- createCertRequest：生成证书请求
- createChildCertificate：生成子证书

为方便调用，针对上述三个接口封装了默认配置（签名算法：SHA256WITHRSA,有效期10年）的生成接口：
- generateRootCertByDefaultConf：生成根证书
- generateCertRequestByDefaultConf：生成证书请求
- generateChildCertByDefaultConf：生成子证书
- generateKPAndRootCert：生成密钥对和根证书

```java
private CertService certService = new CertService();

private static final String SIGNATURE_ALGORITHM = "SHA256WITHRSA";

@Test
public void testGenerateKPAndRootCert(){
    X500NameInfo info = X500NameInfo.builder()
            .commonName("chain")
            .organizationName("fisco-bcos")
            .organizationalUnitName("chain")
            .build();
    //生成相应的密钥对和根证书，并写入指定路径的文件中
    certService.generateKPAndRootCert(info,"out");
}
@Test
public void testGenerateRootCertByDefaultConf(){
    X500NameInfo info = X500NameInfo.builder()
            .commonName("chain")
            .organizationName("fisco-bcos")
            .organizationalUnitName("chain")
            .build();
    String caKey = "[输入私钥key pem string]";
    String caStr = certService.generateRootCertByDefaultConf(info,caKey);
    System.out.println(caStr);
}
    
@Test
public void testGenerateChildCertByDefaultConf(){
    //填入: ca密钥串
    String caKey = "";
    //填入：ca证书字符串
    String caStr = "";
    //填入：子证书请求字符串
    String csrStr = "";
    //第一种方式：参数为字符串
    String childStr = certService.generateChildCertByDefaultConf(caStr,csrStr,caKey);
    System.out.println(childStr);
    //第二种方式：参数为文件路径
//    String childStr2 = certService.generateChildCertByDefaultConf("out/ca.crt","out/child.csr",
//    "out/ca_pri.key", "out/childByFile.crt");
//    System.out.println(childStr2);
}
    
@Test
public void testGenerateCertRequestByDefaultConf(){
    X500NameInfo info = X500NameInfo.builder()
            .commonName("chain")
            .organizationName("fisco-bcos")
            .organizationalUnitName("chain")
            .build();
    KeyPair keyPair = KeyUtils.generateKeyPair();
    String csrStr = certService.generateCertRequestByDefaultConf(info,
    CertUtils.readPEMAsString(keyPair.getPrivate()),"out/child.csr");
//        String csrStr = certService.generateCertRequestByDefaultConf(info,
//        CertUtils.readPEMAsString(keyPair.getPrivate()));
    System.out.println(csrStr);
}
    
@Test
public void testCreateRootCertificate() throws Exception {
    X500NameInfo info = X500NameInfo.builder()
            .commonName("chain")
            .organizationName("fisco-bcos")
            .organizationalUnitName("chain")
            .build();
    KeyPair keyPair = KeyUtils.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    Date beginDate = new Date();
    Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
    X509Certificate certificate = certService.createRootCertificate( SIGNATURE_ALGORITHM, info,
                   null, beginDate,endDate,publicKey,privateKey);
    certificate.verify(publicKey);
    CertUtils.writeCrt(certificate,"out/ca.crt");
}
    
@Test
public void testCreateCertRequest() {
    X500NameInfo info = X500NameInfo.builder()
            .commonName("chain")
            .organizationName("fisco-bcos")
            .organizationalUnitName("chain")
            .build();
    //      ECDSA密钥对,对应csr签名算法为：SHA256WITHECDSA
    //        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
    //        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
    //        keyPairGenerator.initialize(ecGenParameterSpec, SECURE_RANDOM);
    //        KeyPair keyPair = keyPairGenerator.generateKeyPair();
    //        PublicKey publicKey = keyPair.getPublic();
    //        PrivateKey privateKey = keyPair.getPrivate();
    
    KeyPair keyPair = KeyUtils.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    CertUtils.writeKey(privateKey,"out/agency.key");
    PKCS10CertificationRequest request = certService.createCertRequest(info, publicKey, privateKey,
            SIGNATURE_ALGORITHM);
    CertUtils.writeCsr(request, "out/child.csr");
}
    
@Test
public void testCreateChildCertificate() throws Exception {
    Date beginDate = new Date();
    Date endDate = new Date(beginDate.getTime() + 3650 * 24L * 60L * 60L * 1000);
    
    PKCS10CertificationRequest request = CertUtils.readCsr("out/child.csr");
    X509Certificate parentCert = CertUtils.readCrt("out/ca.crt");
    PEMKeyPair pemKeyPair=  CertUtils.readKey("out/ca.key");
    PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(
            new PKCS8EncodedKeySpec(pemKeyPair.getPrivateKeyInfo().getEncoded()));
    X509Certificate childCert = certService.createChildCertificate(true,SIGNATURE_ALGORITHM, parentCert,
                   request,null, beginDate, endDate,privateKey);
    childCert.verify(parentCert.getPublicKey());
}
```




