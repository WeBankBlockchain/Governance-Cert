pkey-mgr组件介绍

# 组件介绍

cert-mgr用于证书托管。

## 证书托管

证书管理中，证书相关的私钥由单独的私钥表保存，还包含了证书表和请求表，生成的证书会保存在证书表中，子证书的请求会保存在请求表中。

证书签名算法目前支持：

*   SHA256WITHRSA
*   SHA256WITHECDSA
*   SM3WITHSM2



## 文档
- [**中文**](https://gov-doc.readthedocs.io/zh_CN/dev/docs/WeBankBlockchain-Gov-Cert/index.html)
- [**cert-mgr使用**](https://gov-doc.readthedocs.io/zh_CN/dev/docs/WeBankBlockchain-Gov-Cert/quickstart2.html)




