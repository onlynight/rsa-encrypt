
package io.github.onlynight.encrypt.rsa;

import org.bouncycastle.util.encoders.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        String filepath = "E:/tmp/";
        encryptDemo(filepath);
    }

    private static void encryptDemo(String filepath) throws Exception {
        System.out.println("--------------公钥加密私钥解密过程-------------------");
        String plainText = "ihep_公钥加密私钥解密";
        byte[] cipherData = RSAEncrypt.encrypt(RSAEncrypt.loadPublicKeyByStr(RSAEncrypt.loadPublicKeyByFile(filepath)), plainText.getBytes());
        byte[] cipher = Base64.encode(cipherData);
        byte[] res = RSAEncrypt.decrypt(RSAEncrypt.loadPrivateKeyByStr(RSAEncrypt.loadPrivateKeyByFile(filepath)), Base64.decode(cipher));
        String restr = new String(res);
        System.out.println("原文：" + plainText);
        System.out.println("加密：" + cipher);
        System.out.println("解密：" + restr);
        System.out.println();

        System.out.println("--------------私钥加密公钥解密过程-------------------");
        plainText = "ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密ihep_公钥加密私钥解密";
        cipherData = RSAEncrypt.encrypt(RSAEncrypt.loadPrivateKeyByStr(RSAEncrypt.loadPrivateKeyByFile(filepath)), plainText.getBytes());
        cipher = Base64.encode(cipherData);
        res = RSAEncrypt.decrypt(RSAEncrypt.loadPublicKeyByStr(RSAEncrypt.loadPublicKeyByFile(filepath)), Base64.decode(cipher));
        restr = new String(res);
        System.out.println("原文：" + plainText);
        System.out.println("加密：" + cipher);
        System.out.println("解密：" + restr);
        System.out.println();

        System.out.println("---------------私钥签名过程------------------");
        String content = "ihep_这是用于签名的原始数据";
        String signstr = RSASignature.sign(content, RSAEncrypt.loadPrivateKeyByFile(filepath));
        System.out.println("签名原串：" + content);
        System.out.println("签名串：" + signstr);
        System.out.println();

        System.out.println("---------------公钥校验签名------------------");
        System.out.println("签名原串：" + content);
        System.out.println("签名串：" + signstr);
        System.out.println("验签结果：" + RSASignature.verify(content, signstr, RSAEncrypt.loadPublicKeyByFile(filepath)));
        System.out.println();
    }
}
