package io.github.onlynight.encrypt.rsa;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAEncrypt {
    private static final int MAX_ENCRYPT_BLOCK = 117;
    private static final int MAX_DECRYPT_BLOCK = 128;
    private static final char[] HEX_CHAR = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    public static final String PRIVATE_KEY_NAME = "rsa_private_key.pem";
    public static final String PUBLIC_KEY_NAME = "rsa_public_key.pem";

    public static void genKeyPair(String filePath) {
        genKeyPair(filePath, 1024);
    }

    public static void genKeyPair(String filePath, int keySize) {
        KeyPairGenerator keyPairGen = null;
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (keyPairGen == null) {
            return;
        }
        keyPairGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        try {
            byte[] publicKeyString = Base64.encode(publicKey.getEncoded());
            byte[] privateKeyString = Base64.encode(privateKey.getEncoded());
            FileWriter pubfw = new FileWriter(filePath + File.separator + "rsa_public_key.pem");
            FileWriter prifw = new FileWriter(filePath + File.separator + "rsa_private_key.pem");
            BufferedWriter pubbw = new BufferedWriter(pubfw);
            BufferedWriter pribw = new BufferedWriter(prifw);
            pubbw.write(new String(publicKeyString));
            pribw.write(new String(privateKeyString));
            pubbw.flush();
            pribw.flush();
            pubbw.close();
            pubfw.close();
            prifw.close();
            pribw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String loadPublicKeyByFile(String path) throws Exception {
        try {
            return getKeyContent(path, "rsa_public_key.pem");
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        }
    }

    public static String loadPrivateKeyByFile(String path) throws Exception {
        try {

            return getKeyContent(path, "rsa_private_key.pem");
        } catch (IOException e) {

            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e) {

            throw new Exception("私钥输入流为空");
        }
    }

    public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr) throws Exception {

        try {

            byte[] buffer = Base64.decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {

            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {

            throw new Exception("公钥非法");
        } catch (NullPointerException e) {

            throw new Exception("公钥数据为空");
        }
    }

    private static String getKeyContent(String path, String keyName) throws IOException {

        return loadEncryptKey(new File(path + File.separator + keyName));
    }

    public static String loadEncryptKey(File encryptFile) throws IOException {

        BufferedReader br = new BufferedReader(new FileReader(encryptFile));
        String readLine = null;
        StringBuilder sb = new StringBuilder();
        while ((readLine = br.readLine()) != null) {
            sb.append(readLine);
        }
        br.close();
        return sb.toString();
    }

    public static String loadEncryptKey(InputStream inputStream) throws IOException {

        BufferedReader br = new BufferedReader(new InputStreamReader(inputStream));
        String readLine = null;
        StringBuilder sb = new StringBuilder();
        while ((readLine = br.readLine()) != null) {
            sb.append(readLine);
        }
        br.close();
        return sb.toString();
    }

    public static RSAPrivateKey loadPrivateKeyByStr(String privateKeyStr) throws Exception {

        try {

            byte[] buffer = Base64.decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {

            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {

            throw new Exception("私钥非法");
        } catch (NullPointerException e) {

            throw new Exception("私钥数据为空");
        }
    }

    public static byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData) throws Exception {

        if (publicKey == null) {
            throw new Exception("加密公钥为空, 请设置");
        }
        Cipher cipher = null;
        try {

            cipher = Cipher.getInstance("RSA");

            cipher.init(1, publicKey);
            return innerCipher(cipher, plainTextData, 117);
        } catch (NoSuchAlgorithmException e) {

            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {

            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {

            throw new Exception("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {

            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {

            throw new Exception("明文数据已损坏");
        }
    }

    public static byte[] encrypt(RSAPrivateKey privateKey, byte[] plainTextData) throws Exception {

        if (privateKey == null) {
            throw new Exception("加密私钥为空, 请设置");
        }
        Cipher cipher = null;
        try {

            cipher = Cipher.getInstance("RSA");
            cipher.init(1, privateKey);
            return innerCipher(cipher, plainTextData, 117);
        } catch (NoSuchAlgorithmException e) {

            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {

            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {

            throw new Exception("加密私钥非法,请检查");
        } catch (IllegalBlockSizeException e) {

            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {

            throw new Exception("明文数据已损坏");
        }
    }

    private static byte[] innerCipher(Cipher cipher, byte[] plainTextData, int maxLength) throws BadPaddingException, IllegalBlockSizeException, IOException {

        int inputLen = plainTextData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;

        int i = 0;
        while (inputLen - offSet > 0) {

            byte[] cache;
            if (inputLen - offSet > maxLength) {
                cache = cipher.doFinal(plainTextData, offSet, maxLength);
            } else {
                cache = cipher.doFinal(plainTextData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * maxLength;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    public static byte[] encrypt(RSAPublicKey publicKey, String data) throws Exception {

        return encrypt(publicKey, data.getBytes());
    }

    public static byte[] encrypt(RSAPrivateKey privateKey, String data) throws Exception {

        return encrypt(privateKey, data.getBytes());
    }

    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData) throws Exception {

        if (privateKey == null) {
            throw new Exception("解密私钥为空, 请设置");
        }
        Cipher cipher = null;
        try {

            cipher = Cipher.getInstance("RSA");

            cipher.init(2, privateKey);
            return innerCipher(cipher, cipherData, 128);
        } catch (NoSuchAlgorithmException e) {

            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {

            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {

            throw new Exception("解密私钥非法,请检查");
        } catch (IllegalBlockSizeException e) {

            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {

            throw new Exception("密文数据已损坏");
        }
    }

    public static byte[] decrypt(RSAPublicKey publicKey, byte[] cipherData) throws Exception {

        if (publicKey == null) {
            throw new Exception("解密公钥为空, 请设置");
        }
        Cipher cipher = null;
        try {

            cipher = Cipher.getInstance("RSA");

            cipher.init(2, publicKey);
            return innerCipher(cipher, cipherData, 128);
        } catch (NoSuchAlgorithmException e) {

            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {

            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {

            throw new Exception("解密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {

            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {

            throw new Exception("密文数据已损坏");
        }
    }

    public static byte[] decrypt(RSAPrivateKey privateKey, String data) throws Exception {

        return decrypt(privateKey, data.getBytes());
    }

    public static byte[] decrypt(RSAPublicKey publicKey, String data) throws Exception {

        return decrypt(publicKey, data.getBytes());
    }

    public static String byteArrayToString(byte[] data) {

        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < data.length; i++) {

            stringBuilder.append(HEX_CHAR[((data[i] & 0xF0) >>> 4)]);

            stringBuilder.append(HEX_CHAR[(data[i] & 0xF)]);
            if (i < data.length - 1) {
                stringBuilder.append(' ');
            }
        }
        return stringBuilder.toString();
    }
}