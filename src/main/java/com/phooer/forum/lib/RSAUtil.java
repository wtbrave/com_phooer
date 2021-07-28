package com.phooer.forum.lib;

import cn.hutool.core.codec.Base64Decoder;
import cn.hutool.core.codec.Base64Encoder;
import org.apache.commons.io.IOUtils;
import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * 加解密工具类
 */
public final class RSAUtil {

    //密钥算法
    public static final String ALGORITHM_RSA                    = "RSA";
    public static final String ALGORITHM_RSA_SIGN               = "SHA1WithRSA";
    public static final int    ALGORITHM_RSA_PRIVATE_KEY_LENGTH = 2048;
    public static final String ALGORITHM_AES                    = "AES";
    public static final String ALGORITHM_AES_PKCS7              = "AES";
    public static final String ALGORITHM_DES                    = "DES";
    public static final String ALGORITHM_DESede                 = "DESede";public static final String SIGN_ALGORITHMS                  = "SHA1WithRSA";


    public static void test() {
        String privateKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCYBXm1yLMXUDZwxzRjOVymVx05lxWkutcOZTNO7j9ovd0c7h4SkoG3JgrBoE3lIV4L8D4lsUejxfKlFOZ06lm5Y/04gMoJA35Ucrin0/9hoiVKIuNwAsP/vZm1IAcQJ8Y+N/iBikV1tpcCp5tSK0eFwqUw+3GdwLeuGcfDMG8h3+XBTGkZccwu7cDSCdRSF3ad5mbyJ1RcI7PzkyiH4n/QxTGpzj4w+AHJk6LH3nIRmNMQnp6TeQAmMwzj6IX3KI5sf4Nnc/okKzeBAYIcSHOyDjeVrfMpRvAsXfmQ7Rsx2LKBcSAw9LOcdMGgLcDkNTOwX3t93vcBxzWMxbZbc+5XAgMBAAECggEAR4TL7amuF5m1Avm0u7mQzPDO3vklRYphAnS53rhXPH+WNrYPj809GVzcUpuICfPYuuUbV8A/Y90Men2KrhZSf9V6m8p7QiJSnIgcN1iVHOmbgXVIarniW75nQb7/k6oiqcLLNqZGZ0qvYKBZgh66V0NrU8/3c6/muhGG2V0/6z8ewMRu22HvxR9xaleAKg1CJL4OJ9LHFeEnd2Um4qgUDRQosk6tpfu1vQf/S8Zivef4j963N+CYx3Yl/O6uT3psu0c9kHRGBLxRNitA02t79gPzlGk8nWqTOdMssKwNM1MTtMhg546fu3PLuVDcdtpug/+OHPeBHN2hoKjkPMlQAQKBgQDkt7u79A2lyVfJ27AJIM6pPtRewL5KF/FiMOSAscfdS9ELnJb2CaTQ/mUysYMZUbiYZqfWb4YchFtSch7G+aIdB1cetsoV5MAc2f+exlHG2xe0ilhHb/P6M9755HfSlGLOgv/W9cfKYcMXp24yKD/NuriVF4uJchDcEU/yrxhu1wKBgQCqJ7IGSg0KkqDN1Kp6ilCKABTuPRfg4OPT4aoFKhK9tegk72WDf5eCsF1dMQMlsyqSJXP/4duimiV3VIXEUc/Om5fHu0a7hWkP3vdVutObsJH/llI1TNwOPtpYQIMeG8wvHwXlmE52GS/Pl4f6iyVP63BIEpWaS5I6JONS+F4MgQKBgQCPeveptDOvkjyhZFDtmQgsQj8F5hI59wU1nQhr95szJ3HPv/8v/+LGPSENCTD9/Dc6XAPkUPgoAZwsf2zxU/8wCL/Ng8wIqgUe1F84op8Aicc4OiWhQwkiJ9I0n+/PSckmViXbGzqnqmax+xX1HyzPidhrp2ag5c7Pz4iA7Pj95wKBgQCKORDfFwydCBvk2NtcDDv8vrBCEBLztPyeRHUPGOx8e+cHCgoW1nFH0uklKQl7eJ4edppSxTDcWAgTde/sWOFM3wxfTfzZnDiKkf+t/sSjdr5DN+O0NKmWUOyiQFXDAaXOqY7qwd0LBs7V/iySFLLMx19AzQgGfVleLlUUM3qDAQKBgQDLCbjw3SCKkJcVERgcnbffcg85hG1UT2A4eyNHry9Xwd2GfwiMzSBOZMhnQNf4NTNZZsMUsbqvyxUslQ6TZxIXjcAsfjCmhsQn9J0SsbyqAxUxgPINSHkPZkUzyyN19g8edg8Lc2g3gKJDxODUYaGwQNzfCyCIBSDZ38mu+0AbYw==";
        String publicKey  = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmAV5tcizF1A2cMc0YzlcplcdOZcVpLrXDmUzTu4/aL3dHO4eEpKBtyYKwaBN5SFeC/A+JbFHo8XypRTmdOpZuWP9OIDKCQN+VHK4p9P/YaIlSiLjcALD/72ZtSAHECfGPjf4gYpFdbaXAqebUitHhcKlMPtxncC3rhnHwzBvId/lwUxpGXHMLu3A0gnUUhd2neZm8idUXCOz85Moh+J/0MUxqc4+MPgByZOix95yEZjTEJ6ek3kAJjMM4+iF9yiObH+DZ3P6JCs3gQGCHEhzsg43la3zKUbwLF35kO0bMdiygXEgMPSznHTBoC3A5DUzsF97fd73Acc1jMW2W3PuVwIDAQAB";
        String data = "supplier_no=78796&user=1432343";

        String a = RSAUtil.buildRSASignByPrivateKey(data, privateKey);
        System.out.println(a);
        boolean b = RSAUtil.buildRSAverifyByPublicKey(data, publicKey, a);
        System.out.println(b);
    }

    /**
     * 初始化RSA算法密钥对
     *
     * @param keysize RSA1024已经不安全了,建议2048
     * @return 经过Base64编码后的公私钥Map, 键名分别为publicKey和privateKey
     */
    public static Map<String, String> initRSAKey(int keysize) {
        if (keysize != ALGORITHM_RSA_PRIVATE_KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "RSA1024已经不安全了,请使用" + ALGORITHM_RSA_PRIVATE_KEY_LENGTH + "初始化RSA密钥对");
        }
        //为RSA算法创建一个KeyPairGenerator对象
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(ALGORITHM_RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm-->[" + ALGORITHM_RSA + "]");
        }
        //初始化KeyPairGenerator对象,不要被initialize()源码表面上欺骗,其实这里声明的size是生效的
        kpg.initialize(ALGORITHM_RSA_PRIVATE_KEY_LENGTH);
        //生成密匙对
        KeyPair keyPair = kpg.generateKeyPair();
        //得到公钥
        Key publicKey = keyPair.getPublic();
        String publicKeyStr = Base64Encoder.encodeUrlSafe(publicKey.getEncoded());
        //得到私钥
        Key privateKey = keyPair.getPrivate();
        String privateKeyStr = Base64Encoder.encodeUrlSafe(privateKey.getEncoded());
        Map<String, String> keyPairMap = new HashMap<String, String>();
        keyPairMap.put("publicKey", publicKeyStr);
        keyPairMap.put("privateKey", privateKeyStr);
        return keyPairMap;
    }


    /**
     * RSA算法公钥加密数据
     *
     * @param data 待加密的明文字符串
     * @param key RSA公钥字符串
     * @return RSA公钥加密后的经过Base64编码的密文字符串
     */
    public static String buildRSAEncryptByPublicKey(String data, String key) {
        try {
            //通过X509编码的Key指令获得公钥对象
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64Decoder.decode(key));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            Key publicKey = keyFactory.generatePublic(x509KeySpec);
            //encrypt
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            //return Base64.encodeBase64URLSafeString(cipher.doFinal(data.getBytes(CHARSET)));
            return Base64Encoder.encodeUrlSafe(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE,
                    data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * RSA算法公钥解密数据
     *
     * @param data 待解密的经过Base64编码的密文字符串
     * @param key RSA公钥字符串
     * @return RSA公钥解密后的明文字符串
     */
    public static String buildRSADecryptByPublicKey(String data, String key) {
        try {
            //通过X509编码的Key指令获得公钥对象
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64Decoder.decode(key));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            Key publicKey = keyFactory.generatePublic(x509KeySpec);
            //decrypt
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return new String(
                    rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64Decoder.decode(data)),
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * RSA算法私钥加密数据
     *
     * @param data 待加密的明文字符串
     * @param key RSA私钥字符串
     * @return RSA私钥加密后的经过Base64编码的密文字符串
     */
    public static String buildRSAEncryptByPrivateKey(String data, String key) {
        try {
            //通过PKCS#8编码的Key指令获得私钥对象
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64Decoder.decode(key));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
            //encrypt
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            //return Base64.encodeBase64URLSafeString(cipher.doFinal(data.getBytes(CHARSET)));
            return Base64Encoder.encodeUrlSafe(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE,
                    data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * RSA算法私钥解密数据
     *
     * @param data 待解密的经过Base64编码的密文字符串
     * @param key RSA私钥字符串
     * @return RSA私钥解密后的明文字符串
     */
    public static String buildRSADecryptByPrivateKey(String data, String key) {
        try {
            //通过PKCS#8编码的Key指令获得私钥对象
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64Decoder.decode(key));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
            //decrypt
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            //return new String(cipher.doFinal(Base64.decodeBase64(data)), CHARSET);
            return new String(
                    rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64Decoder.decode(data)),
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * RSA算法使用私钥对数据生成数字签名
     *
     * @param data 待签名的明文字符串
     * @param key RSA私钥字符串
     * @return RSA私钥签名后的经过Base64编码的字符串
     */
    public static String buildRSASignByPrivateKey(String data, String key) {
        try {
            //通过PKCS#8编码的Key指令获得私钥对象
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64Decoder.decode(key));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
            //sign
            Signature signature = Signature.getInstance(ALGORITHM_RSA_SIGN);
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return Base64Encoder.encodeUrlSafe(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException("签名字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * RSA算法使用公钥校验数字签名
     *
     * @param data 参与签名的明文字符串
     * @param key RSA公钥字符串
     * @param sign RSA签名得到的经过Base64编码的字符串
     * @return true--验签通过,false--验签未通过
     */
    public static boolean buildRSAverifyByPublicKey(String data, String key, String sign) {
        try {
            //通过X509编码的Key指令获得公钥对象
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64Decoder.decode(key));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
            //verify
            Signature signature = Signature.getInstance(ALGORITHM_RSA_SIGN);
            signature.initVerify(publicKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64Decoder.decode(sign));
        } catch (Exception e) {
            throw new RuntimeException("验签字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * RSA算法分段加解密数据
     *
     * @param cipher 初始化了加解密工作模式后的javax.crypto.Cipher对象
     * @param opmode 加解密模式,值为javax.crypto.Cipher.ENCRYPT_MODE/DECRYPT_MODE
     * @return 加密或解密后得到的数据的字节数组
     */
    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas) {
        int maxBlock;
        if (opmode == Cipher.DECRYPT_MODE) {
            maxBlock = ALGORITHM_RSA_PRIVATE_KEY_LENGTH / 8;
        } else {
            maxBlock = ALGORITHM_RSA_PRIVATE_KEY_LENGTH / 8 - 11;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] buff;
        int i = 0;
        try {
            while (datas.length > offSet) {
                if (datas.length - offSet > maxBlock) {
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                } else {
                    buff = cipher.doFinal(datas, offSet, datas.length - offSet);
                }
                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
        } catch (Exception e) {
            throw new RuntimeException("加解密阀值为[" + maxBlock + "]的数据时发生异常", e);
        }
        byte[] resultDatas = out.toByteArray();
        IOUtils.closeQuietly(out);
        return resultDatas;
    }


    /**
     * 用私钥签名
     */
    public static String signByPrivateKey(String content, String privateKey) {
        try {
            PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(Base64Decoder.decode(privateKey));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8);
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initSign(priKey);
            signature.update(content.getBytes(StandardCharsets.UTF_8));
            byte[] signed = signature.sign();
            return Base64Encoder.encode(signed);
        } catch (Exception e) {
            throw new RuntimeException("数据[" + content + "]签名出现异常", e);
        }
    }

    /**
     * 用公钥解密
     */
    public static String decryptByPublicKey(String content, String key) {
        if (null == key || "".equals(key)) {
            return null;
        }
        PublicKey pk = getPublicKey(key);
        byte[] data = decryptByPublicKey(content, pk);
        if (data == null) {
            throw new RuntimeException("数据[" + content + "]解密出现异常");
        }
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * 获取公钥对象
     *
     * 密钥字符串（经过base64编码秘钥字节）
     */
    private static PublicKey getPublicKey(String publicKey) {
        try {
            byte[] keyBytes;
            keyBytes = Base64Decoder.decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publickey = keyFactory.generatePublic(keySpec);
            return publickey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 通过公钥解密
     *
     * @return 返回 解密后的数据
     */
    private static byte[] decryptByPublicKey(String content, PublicKey pk) {
        try {
            Cipher ch = Cipher.getInstance(ALGORITHM_RSA);
            ch.init(Cipher.DECRYPT_MODE, pk);
            InputStream ins = new ByteArrayInputStream(Base64Decoder.decode(content));
            ByteArrayOutputStream writer = new ByteArrayOutputStream();
            byte[] buf = new byte[2048];
            int bufl;
            while ((bufl = ins.read(buf)) != -1) {
                byte[] block;

                if (buf.length == bufl) {
                    block = buf;
                } else {
                    block = new byte[bufl];
                    for (int i = 0; i < bufl; i++) {
                        block[i] = buf[i];
                    }
                }
                writer.write(ch.doFinal(block));
            }
            return writer.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
