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

    public static String loadPrivateKeyByFile(String path)
            throws Exception {
        /* 107:    */
        try
            /* 108:    */ {
            /* 109:120 */
            return getKeyContent(path, "rsa_private_key.pem");
            /* 110:    */
        }
        /* 111:    */ catch (IOException e)
            /* 112:    */ {
            /* 113:122 */
            throw new Exception("私钥数据读取错误");
            /* 114:    */
        }
        /* 115:    */ catch (NullPointerException e)
            /* 116:    */ {
            /* 117:124 */
            throw new Exception("私钥输入流为空");
            /* 118:    */
        }
        /* 119:    */
    }

    /* 120:    */
    /* 121:    */
    public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr)
    /* 122:    */     throws Exception
    /* 123:    */ {
        /* 124:    */
        try
            /* 125:    */ {
            /* 126:137 */
            byte[] buffer = Base64.decode(publicKeyStr);
            /* 127:138 */
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            /* 128:139 */
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            /* 129:140 */
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
            /* 130:    */
        }
        /* 131:    */ catch (NoSuchAlgorithmException e)
            /* 132:    */ {
            /* 133:142 */
            throw new Exception("无此算法");
            /* 134:    */
        }
        /* 135:    */ catch (InvalidKeySpecException e)
            /* 136:    */ {
            /* 137:144 */
            throw new Exception("公钥非法");
            /* 138:    */
        }
        /* 139:    */ catch (NullPointerException e)
            /* 140:    */ {
            /* 141:146 */
            throw new Exception("公钥数据为空");
            /* 142:    */
        }
        /* 143:    */
    }

    /* 144:    */
    /* 145:    */
    private static String getKeyContent(String path, String keyName)
    /* 146:    */     throws IOException
    /* 147:    */ {
        /* 148:151 */
        return loadEncryptKey(new File(path + File.separator + keyName));
        /* 149:    */
    }

    /* 150:    */
    /* 151:    */
    public static String loadEncryptKey(File encryptFile)
    /* 152:    */     throws IOException
    /* 153:    */ {
        /* 154:162 */
        BufferedReader br = new BufferedReader(new FileReader(encryptFile));
        /* 155:163 */
        String readLine = null;
        /* 156:164 */
        StringBuilder sb = new StringBuilder();
        /* 157:165 */
        while ((readLine = br.readLine()) != null) {
            /* 158:166 */
            sb.append(readLine);
            /* 159:    */
        }
        /* 160:168 */
        br.close();
        /* 161:169 */
        return sb.toString();
        /* 162:    */
    }

    /* 163:    */
    /* 164:    */
    public static RSAPrivateKey loadPrivateKeyByStr(String privateKeyStr)
    /* 165:    */     throws Exception
    /* 166:    */ {
        /* 167:    */
        try
            /* 168:    */ {
            /* 169:175 */
            byte[] buffer = Base64.decode(privateKeyStr);
            /* 170:176 */
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            /* 171:177 */
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            /* 172:178 */
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
            /* 173:    */
        }
        /* 174:    */ catch (NoSuchAlgorithmException e)
            /* 175:    */ {
            /* 176:180 */
            throw new Exception("无此算法");
            /* 177:    */
        }
        /* 178:    */ catch (InvalidKeySpecException e)
            /* 179:    */ {
            /* 180:182 */
            throw new Exception("私钥非法");
            /* 181:    */
        }
        /* 182:    */ catch (NullPointerException e)
            /* 183:    */ {
            /* 184:184 */
            throw new Exception("私钥数据为空");
            /* 185:    */
        }
        /* 186:    */
    }

    /* 187:    */
    /* 188:    */
    public static byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData)
    /* 189:    */     throws Exception
    /* 190:    */ {
        /* 191:198 */
        if (publicKey == null) {
            /* 192:199 */
            throw new Exception("加密公钥为空, 请设置");
            /* 193:    */
        }
        /* 194:201 */
        Cipher cipher = null;
        /* 195:    */
        try
            /* 196:    */ {
            /* 197:204 */
            cipher = Cipher.getInstance("RSA");
            /* 198:    */
            /* 199:206 */
            cipher.init(1, publicKey);
            /* 200:207 */
            return innerCipher(cipher, plainTextData, 117);
            /* 201:    */
        }
        /* 202:    */ catch (NoSuchAlgorithmException e)
            /* 203:    */ {
            /* 204:209 */
            throw new Exception("无此加密算法");
            /* 205:    */
        }
        /* 206:    */ catch (NoSuchPaddingException e)
            /* 207:    */ {
            /* 208:211 */
            e.printStackTrace();
            /* 209:212 */
            return null;
            /* 210:    */
        }
        /* 211:    */ catch (InvalidKeyException e)
            /* 212:    */ {
            /* 213:214 */
            throw new Exception("加密公钥非法,请检查");
            /* 214:    */
        }
        /* 215:    */ catch (IllegalBlockSizeException e)
            /* 216:    */ {
            /* 217:216 */
            throw new Exception("明文长度非法");
            /* 218:    */
        }
        /* 219:    */ catch (BadPaddingException e)
            /* 220:    */ {
            /* 221:218 */
            throw new Exception("明文数据已损坏");
            /* 222:    */
        }
        /* 223:    */
    }

    /* 224:    */
    /* 225:    */
    public static byte[] encrypt(RSAPrivateKey privateKey, byte[] plainTextData)
    /* 226:    */     throws Exception
    /* 227:    */ {
        /* 228:232 */
        if (privateKey == null) {
            /* 229:233 */
            throw new Exception("加密私钥为空, 请设置");
            /* 230:    */
        }
        /* 231:235 */
        Cipher cipher = null;
        /* 232:    */
        try
            /* 233:    */ {
            /* 234:238 */
            cipher = Cipher.getInstance("RSA");
            /* 235:239 */
            cipher.init(1, privateKey);
            /* 236:240 */
            return innerCipher(cipher, plainTextData, 117);
            /* 237:    */
        }
        /* 238:    */ catch (NoSuchAlgorithmException e)
            /* 239:    */ {
            /* 240:242 */
            throw new Exception("无此加密算法");
            /* 241:    */
        }
        /* 242:    */ catch (NoSuchPaddingException e)
            /* 243:    */ {
            /* 244:244 */
            e.printStackTrace();
            /* 245:245 */
            return null;
            /* 246:    */
        }
        /* 247:    */ catch (InvalidKeyException e)
            /* 248:    */ {
            /* 249:247 */
            throw new Exception("加密私钥非法,请检查");
            /* 250:    */
        }
        /* 251:    */ catch (IllegalBlockSizeException e)
            /* 252:    */ {
            /* 253:249 */
            throw new Exception("明文长度非法");
            /* 254:    */
        }
        /* 255:    */ catch (BadPaddingException e)
            /* 256:    */ {
            /* 257:251 */
            throw new Exception("明文数据已损坏");
            /* 258:    */
        }
        /* 259:    */
    }

    /* 260:    */
    /* 261:    */
    private static byte[] innerCipher(Cipher cipher, byte[] plainTextData, int maxLength)
    /* 262:    */     throws BadPaddingException, IllegalBlockSizeException, IOException
    /* 263:    */ {
        /* 264:256 */
        int inputLen = plainTextData.length;
        /* 265:257 */
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        /* 266:258 */
        int offSet = 0;
        /* 267:    */
        /* 268:260 */
        int i = 0;
        /* 269:261 */
        while (inputLen - offSet > 0)
            /* 270:    */ {
            /* 271:    */
            byte[] cache;
            /* 273:262 */
            if (inputLen - offSet > maxLength) {
                /* 274:263 */
                cache = cipher.doFinal(plainTextData, offSet, maxLength);
                /* 275:    */
            } else {
                /* 276:265 */
                cache = cipher.doFinal(plainTextData, offSet, inputLen - offSet);
                /* 277:    */
            }
            /* 278:267 */
            out.write(cache, 0, cache.length);
            /* 279:268 */
            i++;
            /* 280:269 */
            offSet = i * maxLength;
            /* 281:    */
        }
        /* 282:271 */
        byte[] decryptedData = out.toByteArray();
        /* 283:272 */
        out.close();
        /* 284:273 */
        return decryptedData;
        /* 285:    */
    }

    /* 286:    */
    /* 287:    */
    public static byte[] encrypt(RSAPublicKey publicKey, String data)
    /* 288:    */     throws Exception
    /* 289:    */ {
        /* 290:286 */
        return encrypt(publicKey, data.getBytes());
        /* 291:    */
    }

    /* 292:    */
    /* 293:    */
    public static byte[] encrypt(RSAPrivateKey privateKey, String data)
    /* 294:    */     throws Exception
    /* 295:    */ {
        /* 296:298 */
        return encrypt(privateKey, data.getBytes());
        /* 297:    */
    }

    /* 298:    */
    /* 299:    */
    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData)
    /* 300:    */     throws Exception
    /* 301:    */ {
        /* 302:311 */
        if (privateKey == null) {
            /* 303:312 */
            throw new Exception("解密私钥为空, 请设置");
            /* 304:    */
        }
        /* 305:314 */
        Cipher cipher = null;
        /* 306:    */
        try
            /* 307:    */ {
            /* 308:317 */
            cipher = Cipher.getInstance("RSA");
            /* 309:    */
            /* 310:319 */
            cipher.init(2, privateKey);
            /* 311:320 */
            return innerCipher(cipher, cipherData, 128);
            /* 312:    */
        }
        /* 313:    */ catch (NoSuchAlgorithmException e)
            /* 314:    */ {
            /* 315:322 */
            throw new Exception("无此解密算法");
            /* 316:    */
        }
        /* 317:    */ catch (NoSuchPaddingException e)
            /* 318:    */ {
            /* 319:324 */
            e.printStackTrace();
            /* 320:325 */
            return null;
            /* 321:    */
        }
        /* 322:    */ catch (InvalidKeyException e)
            /* 323:    */ {
            /* 324:327 */
            throw new Exception("解密私钥非法,请检查");
            /* 325:    */
        }
        /* 326:    */ catch (IllegalBlockSizeException e)
            /* 327:    */ {
            /* 328:329 */
            throw new Exception("密文长度非法");
            /* 329:    */
        }
        /* 330:    */ catch (BadPaddingException e)
            /* 331:    */ {
            /* 332:331 */
            throw new Exception("密文数据已损坏");
            /* 333:    */
        }
        /* 334:    */
    }

    /* 335:    */
    /* 336:    */
    public static byte[] decrypt(RSAPublicKey publicKey, byte[] cipherData)
    /* 337:    */     throws Exception
    /* 338:    */ {
        /* 339:345 */
        if (publicKey == null) {
            /* 340:346 */
            throw new Exception("解密公钥为空, 请设置");
            /* 341:    */
        }
        /* 342:348 */
        Cipher cipher = null;
        /* 343:    */
        try
            /* 344:    */ {
            /* 345:351 */
            cipher = Cipher.getInstance("RSA");
            /* 346:    */
            /* 347:353 */
            cipher.init(2, publicKey);
            /* 348:354 */
            return innerCipher(cipher, cipherData, 128);
            /* 349:    */
        }
        /* 350:    */ catch (NoSuchAlgorithmException e)
            /* 351:    */ {
            /* 352:356 */
            throw new Exception("无此解密算法");
            /* 353:    */
        }
        /* 354:    */ catch (NoSuchPaddingException e)
            /* 355:    */ {
            /* 356:358 */
            e.printStackTrace();
            /* 357:359 */
            return null;
            /* 358:    */
        }
        /* 359:    */ catch (InvalidKeyException e)
            /* 360:    */ {
            /* 361:361 */
            throw new Exception("解密公钥非法,请检查");
            /* 362:    */
        }
        /* 363:    */ catch (IllegalBlockSizeException e)
            /* 364:    */ {
            /* 365:363 */
            throw new Exception("密文长度非法");
            /* 366:    */
        }
        /* 367:    */ catch (BadPaddingException e)
            /* 368:    */ {
            /* 369:365 */
            throw new Exception("密文数据已损坏");
            /* 370:    */
        }
        /* 371:    */
    }

    /* 372:    */
    /* 373:    */
    public static byte[] decrypt(RSAPrivateKey privateKey, String data)
    /* 374:    */     throws Exception
    /* 375:    */ {
        /* 376:379 */
        return decrypt(privateKey, data.getBytes());
        /* 377:    */
    }

    /* 378:    */
    /* 379:    */
    public static byte[] decrypt(RSAPublicKey publicKey, String data)
    /* 380:    */     throws Exception
    /* 381:    */ {
        /* 382:392 */
        return decrypt(publicKey, data.getBytes());
        /* 383:    */
    }

    /* 384:    */
    /* 385:    */
    public static String byteArrayToString(byte[] data)
    /* 386:    */ {
        /* 387:402 */
        StringBuilder stringBuilder = new StringBuilder();
        /* 388:403 */
        for (int i = 0; i < data.length; i++)
            /* 389:    */ {
            /* 390:405 */
            stringBuilder.append(HEX_CHAR[((data[i] & 0xF0) >>> 4)]);
            /* 391:    */
            /* 392:407 */
            stringBuilder.append(HEX_CHAR[(data[i] & 0xF)]);
            /* 393:408 */
            if (i < data.length - 1) {
                /* 394:409 */
                stringBuilder.append(' ');
                /* 395:    */
            }
            /* 396:    */
        }
        /* 397:412 */
        return stringBuilder.toString();
        /* 398:    */
    }
    /* 399:    */
}



/* Location:           C:\Users\zhangwenda\Desktop\rsa-encrypt-1.0-SNAPSHOT.jar

 * Qualified Name:     io.github.onlynight.encrypt.rsa.RSAEncrypt

 * JD-Core Version:    0.7.0.1

 */