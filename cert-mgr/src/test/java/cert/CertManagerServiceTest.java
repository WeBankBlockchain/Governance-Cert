package cert;

import cert.enums.KeyAlgorithmEnums;
import cert.model.vo.CertKeyVO;
import cert.model.vo.CertRequestVO;
import cert.model.vo.CertVO;
import cert.service.CertManagerService;
import com.webank.cert.constants.CertConstants;
import com.webank.cert.model.X500NameInfo;
import com.webank.cert.utils.CertUtils;
import com.webank.cert.utils.KeyUtils;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.web3j.utils.Numeric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020-05-20
 */
public class CertManagerServiceTest extends BaseTest {

    @Autowired
    private CertManagerService certManagerService;


    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testCreateRootCert0() throws Exception{
        X500NameInfo issuer = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();
        String userId = "wangyue";
        String cert = certManagerService.createRootCert(userId,issuer).getCertContent();
        System.out.println(cert);
    }

    @Test
    public void testCreateRootCert1() throws Exception{
        X500NameInfo issuer = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();
        String userId = "wangyue";
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + CertConstants.DEFAULT_VALIDITY);
        String cert = certManagerService.createRootCert(userId,issuer,beginDate,endDate).getCertContent();
        System.out.println(cert);
    }

    @Test
    public void testCreateRootCert2() throws Exception{
        X500NameInfo issuer = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();
        String userId = "wangyue";
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + CertConstants.DEFAULT_VALIDITY);
        String cert = certManagerService.createRootCert(userId,1,issuer,beginDate,endDate).getCertContent();
        System.out.println(cert);
    }

    @Test
    public void testCreateRootCert3() throws Exception{
        X500NameInfo issuer = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();
        String userId = "wangyue";
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + CertConstants.DEFAULT_VALIDITY);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.dataEncipherment);
        String cert = certManagerService.createRootCert(userId,1,issuer,keyUsage,beginDate,endDate).getCertContent();
        System.out.println(cert);
    }

    @Test
    public void testCreateRootCert4() throws Exception{
        X500NameInfo issuer = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();
        String userId = "wangyue";
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + CertConstants.DEFAULT_VALIDITY);
        String pemPriKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEogIBAAKCAQEAwgHqJvevMzTeoQngSkdMidRr0zTP5U2MHZyt9nyZZrGGrFTW\n" +
                "YmkVLRYyPH6eGmiTAFwK30v+bpDjdZHwEzFFO7yObKN6LeyByP/xuDenmUWmEcXK\n" +
                "8/6aqtlx38nmsuMJj5V9Xrf/Q9gLs1a52foHml9oTYKq2mEeaQBT9Kwxcwae9AbP\n" +
                "ChVTg39UBWVvFV0//Dx+OFV3Jp185XPkrfRsrxrf6KwoU4cewY0exM1AtSpazsOm\n" +
                "zfq1bBzjgHw4LWxeyTlZb++jz/gcFZBuFUTjgFiogqPuM85YJLI73S826KYVYw5i\n" +
                "Htn9NtM65ldgFEv+lm/gRtM65uaiW06p0bB+cwIDAQABAoIBAG49mEg8Rhna2Qa5\n" +
                "DfInQZ6wTfTd9aRexFevSErf0mtART53lrqk65uLGVC2wjBPa/iwVJ0+GX3KZvXP\n" +
                "z5OYU7b2Fhg1bJ/b3IPSrA/50AqQQSWoNwMekdSzarm3iJft2uj0ESFZfHuYsE1f\n" +
                "4ouyP8/Alww0S9F7jkQsI4jMr+yjwNBN8wg85mTcksgHlAI4QJJAEAbH8tPca436\n" +
                "yIZaGdBXsqWRBXWLr2vfmhAJabTGRonS+Gbuw51uwx2HvtjaISY87Yy4YqpeWvPp\n" +
                "ItMaqd/tv3jC1JyULPcnsfWVoUEsUAQP8yWxyI7VGIPgkGaHABfTATm0tKGaTa7K\n" +
                "5IlypQECgYEA6+SgsUOTYr3AgK9r8YkyVeqzUl5MCpKGlVdG4LI4SAlW2kdB8yqO\n" +
                "sLJycEVrkGefd/jtutX52GTW0mp6n+wProka4R9ygb3f1NaO52spapUtslo8JHIn\n" +
                "08l3SYt1grGuDqrOMgIeMEJFURqYWXYh0zyEwqfAM+BKxwkaiQtoTbECgYEA0otP\n" +
                "b4KI4RY8te/jaOmE6925/aoG1A1bmMlciowh/fgxOIT1GnFHztpC14asB4luioNj\n" +
                "aFqBJfo5P81IniK5LPnLSsR8ll2KWwdSwwT5yAm/V1f1v0/ATIOQdJ7GlKfxzb4i\n" +
                "qUgXKKCJ5zRWq/AcYAtPTwd35iaRaaPBt1//Y2MCgYBBFnVsU+v/68GJAF41aBi2\n" +
                "cisGiDRNGn7+B/Xrm+FBpyoK0myVDuIOST6gUddLIfxzWwElc1Mb7T8FEhJBvB3b\n" +
                "l8MN6OJsgBqZnJYTrpLf8MeKFbHQkJsCqe07IrrK1AHl1CVO0RzJTg/YQBFXZewR\n" +
                "X/p1x1mWNsYLQyzKMZaXEQKBgF/UIoqpii2Q1n8kuYf1yZcla1MmgUcg8VDgTauN\n" +
                "zqbuwVBtS7YGW12uAABi/ofLqLGIzcUgdGnZsxb0E5pOSaRL6ZiVR/OUjbWS5rt2\n" +
                "102SCjHyChtSbD8nHqfF4LKmois34ETWWBwYvcurCcvmVLPuUeGxj4QEh+jiLPiO\n" +
                "zAnrAoGAdUXU3EHRTe+rMvI0PPt6U6wIxS4yPxTmDBwUp7QANGcnWcJtU4L9v1c3\n" +
                "FUYldP6MPtD3UWxuryw61v1BWWQvUh3fl1WyxWVhq1RkPfMkUEqUCKBXrj1F2BCO\n" +
                "qb+qz+H6MpYzUvAOmtQIBSqCcFpy7aKb/CFe5tJjo0EbGghIErY=\n" +
                "-----END RSA PRIVATE KEY-----\n";

        String str = certManagerService.createRootCert(userId,pemPriKey, KeyAlgorithmEnums.RSA,issuer,beginDate,endDate).getCertContent();
        System.out.println(str);
    }


    @Test
    public void testCreateRootCertByHexPriKey() throws Exception{
        X500NameInfo issuer = X500NameInfo.builder()
                .commonName("chain")
                .organizationName("fisco-bcos")
                .organizationalUnitName("chain")
                .build();
        String userId = "wangyue";
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + CertConstants.DEFAULT_VALIDITY);
        KeyPair keyPair = KeyUtils.generateKeyPair();
        String hexPriKey = Numeric.toHexString(keyPair.getPrivate().getEncoded());
        String cert = certManagerService.createRootCertByHexPriKey(userId,hexPriKey,KeyAlgorithmEnums.RSA,issuer,beginDate,endDate).getCertContent();
        System.out.println(cert);
    }


    @Test
    public void testCreateCertRequestByHexPriKey() throws Exception{
        X500NameInfo subject = X500NameInfo.builder()
                .commonName("agancy")
                .organizationName("fisco-bcos")
                .organizationalUnitName("agancy")
                .build();
        String userId = "wangyue";
        String hexPriKey = "3500db68433dda968ef7bfe5a0ed6926b8e85aabcd2caa54f8327ca07ac73526";
        String cert = certManagerService.createCertRequestByHexPriKey(userId,hexPriKey,KeyAlgorithmEnums.ECDSA,3,subject).getCertRequestContent();
        System.out.println(cert);
    }


    @Test
    public void testCreateCertRequest0() throws Exception{
        X500NameInfo subject = X500NameInfo.builder()
                .commonName("agancy")
                .organizationName("fisco-bcos")
                .organizationalUnitName("agancy")
                .build();
        String userId = "wangyue1";
        String csr;
        csr = certManagerService.createCertRequest(userId,1, subject).getCertRequestContent();
        System.out.println(csr);
    }

    @Test
    public void testCreateCertRequest1() throws Exception{
        X500NameInfo subject = X500NameInfo.builder()
                .commonName("agancy")
                .organizationName("fisco-bcos")
                .organizationalUnitName("agancy")
                .build();
        String userId = "wangyue1";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        String csr = certManagerService.createCertRequest(userId, CertUtils.readPEMAsString(privateKey),
                KeyAlgorithmEnums.ECDSA,1,subject).getCertRequestContent();
        System.out.println(csr);
    }


    @Test
    public void testCreateChildCert() throws Exception{
        String userId = "wangyue1";
        String child;
        child = certManagerService.createChildCert(userId,4).getCertContent();
        System.out.println(child);
    }


    @Test
    public void testResetCertificate() throws Exception{
        String userId = "wangyue1";
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + CertConstants.DEFAULT_VALIDITY);
        String root = certManagerService.resetCertificate(userId,9,
                new KeyUsage(KeyUsage.dataEncipherment),
                beginDate,endDate).getCertContent();
        System.out.println(root);
    }

    @Test
    public void testQueryCertList() {
        String userId = "wangyue";
        List<CertVO> list = certManagerService.queryCertList(
                userId,null,null,null,null,null);
        System.out.println();
    }

    @Test
    public void testQueryCertRequestList() {
        String userId = "wangyue";
        List<CertRequestVO> list = certManagerService.queryCertRequestList(
                userId,null,null,null,null,null);
        System.out.println();
    }

    @Test
    public void testQueryCertKeyList() {
        String userId = "wangyue";
        List<CertKeyVO> list = certManagerService.queryCertKeyList(userId);
        System.out.println();
    }


    @Test
    public void testQueryCertInfoByCertId() {
        CertVO certInfo = certManagerService.queryCertInfoByCertId(1L);
        System.out.println();
    }

    @Test
    public void testQueryCertRequestByCsrId() {
        CertRequestVO keyRequestVO = certManagerService.queryCertRequestByCsrId(1L);
        System.out.println();
    }

    @Test
    public void testExportCertToFile() throws Exception {
        certManagerService.exportCertToFile(1L,"src/ca.crt");
        System.out.println();
    }

}
