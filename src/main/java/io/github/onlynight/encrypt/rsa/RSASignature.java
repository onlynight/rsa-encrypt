/*   1:    */
package io.github.onlynight.encrypt.rsa;
/*   2:    */
/*   4:    */

import org.bouncycastle.util.encoders.Base64;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSASignature {
    private static final String SIGN_ALGORITHMS = "SHA1WithRSA";

    public static String sign(String content, String privateKey, String encode)
        /*  16:    */ {
        /*  17:    */
        try
            /*  18:    */ {
            /*  19: 32 */
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
            /*  20:    */
            /*  21: 34 */
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            /*  22: 35 */
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            /*  23:    */
            /*  24: 37 */
            Signature signature = Signature.getInstance("SHA1WithRSA");
            /*  25:    */
            /*  26: 39 */
            signature.initSign(priKey);
            /*  27: 40 */
            signature.update(content.getBytes(encode));
            /*  28:    */
            /*  29: 42 */
            byte[] signed = signature.sign();
            /*  30:    */
            /*  31: 44 */
            return new String(Base64.encode(signed));
            /*  32:    */
        }
        /*  33:    */ catch (Exception e)
            /*  34:    */ {
            /*  35: 46 */
            e.printStackTrace();
            /*  36:    */
        }
        /*  37: 49 */
        return null;
        /*  38:    */
    }

    /*  39:    */
    /*  40:    */
    public static String sign(String content, String privateKey)
    /*  41:    */ {
        /*  42:    */
        try
            /*  43:    */ {
            /*  44: 54 */
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
            /*  45: 55 */
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            /*  46: 56 */
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            /*  47: 57 */
            Signature signature = Signature.getInstance("SHA1WithRSA");
            /*  48: 58 */
            signature.initSign(priKey);
            /*  49: 59 */
            signature.update(content.getBytes());
            /*  50: 60 */
            byte[] signed = signature.sign();
            /*  51: 61 */
            return new String(Base64.encode(signed));
            /*  52:    */
        }
        /*  53:    */ catch (Exception e)
            /*  54:    */ {
            /*  55: 63 */
            e.printStackTrace();
            /*  56:    */
        }
        /*  57: 65 */
        return null;
        /*  58:    */
    }

    /*  59:    */
    /*  60:    */
    public static boolean verify(String content, String sign, String publicKey, String encode)
    /*  61:    */ {
        /*  62:    */
        try
            /*  63:    */ {
            /*  64: 79 */
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            /*  65: 80 */
            byte[] encodedKey = Base64.decode(publicKey);
            /*  66: 81 */
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
            /*  67:    */
            /*  68:    */
            /*  69:    */
            /*  70: 85 */
            Signature signature = Signature.getInstance("SHA1WithRSA");
            /*  71:    */
            /*  72: 87 */
            signature.initVerify(pubKey);
            /*  73: 88 */
            signature.update(content.getBytes(encode));
            /*  74:    */
            /*  75: 90 */
            return signature.verify(Base64.decode(sign));
            /*  76:    */
        }
        /*  77:    */ catch (Exception e)
            /*  78:    */ {
            /*  79: 93 */
            e.printStackTrace();
            /*  80:    */
        }
        /*  81: 96 */
        return false;
        /*  82:    */
    }

    /*  83:    */
    /*  84:    */
    public static boolean verify(String content, String sign, String publicKey)
    /*  85:    */ {
        /*  86:    */
        try
            /*  87:    */ {
            /*  88:101 */
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            /*  89:102 */
            byte[] encodedKey = Base64.decode(publicKey);
            /*  90:103 */
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
            /*  91:    */
            /*  92:    */
            /*  93:    */
            /*  94:107 */
            Signature signature = Signature.getInstance("SHA1WithRSA");
            /*  95:    */
            /*  96:109 */
            signature.initVerify(pubKey);
            /*  97:110 */
            signature.update(content.getBytes());
            /*  98:    */
            /*  99:112 */
            return signature.verify(Base64.decode(sign));
            /* 100:    */
        }
        /* 101:    */ catch (Exception e)
            /* 102:    */ {
            /* 103:116 */
            e.printStackTrace();
            /* 104:    */
        }
        /* 105:119 */
        return false;
        /* 106:    */
    }
    /* 107:    */
}



/* Location:           C:\Users\zhangwenda\Desktop\rsa-encrypt-1.0-SNAPSHOT.jar

 * Qualified Name:     io.github.onlynight.encrypt.rsa.RSASignature

 * JD-Core Version:    0.7.0.1

 */