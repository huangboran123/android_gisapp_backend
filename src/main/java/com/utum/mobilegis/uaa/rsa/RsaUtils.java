package com.utum.mobilegis.uaa.rsa;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.codec.Base64;

import com.alibaba.fastjson.JSONObject;
import com.utum.mobilegis.domain.GisUser;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * RSA工具
 */
public class RsaUtils {

    private final static Charset UTF8 = StandardCharsets.UTF_8;

    public static String getPrivateKeyStr(PrivateKey privateKey) throws Exception {
        return new String(Base64.encode(privateKey.getEncoded()));
    }

    public static String getPublicKeyStr(PublicKey publicKey) throws Exception {
        return new String(Base64.encode(publicKey.getEncoded()));
    }

    /**
     * RSA公钥加密
     *
     * @param str       明文信息
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encrypt(String str, String publicKey) throws Exception {
        //base64编码的公钥
        byte[] decoded = Base64.decode(publicKey);

        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        String outStr = null;
        byte[] inputArray = str.getBytes("UTF-8");
        int inputLength = inputArray.length;
        // 最大加密字节数，超出最大字节数需要分组加密
        int MAX_ENCRYPT_BLOCK = 117;
        // 标识
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] cache = {};
        while (inputLength - offSet > 0) {
            if (inputLength - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                cache = cipher.doFinal(inputArray, offSet, inputLength - offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
            System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
        }
        return Base64.encode(resultBytes);
    }

    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 密文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt(String str, String privateKey) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decode(str.getBytes("UTF-8"));
        //base64编码的私钥
        byte[] decoded = Base64.decode(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);

        String outStr = null;
        int inputLength = inputByte.length;
        // 最大加密字节数，超出最大字节数需要分组加密
        int MAX_ENCRYPT_BLOCK = 128;
        // 标识
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] cache = {};
        while (inputLength - offSet > 0) {
            if (inputLength - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(inputByte, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                cache = cipher.doFinal(inputByte, offSet, inputLength - offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
            System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
        }
        return new String(resultBytes, "UTF-8");
    }

    /**
     * RSA私钥加密
     *
     * @param str
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static String privateKeyEncrypt(String str, String privateKey) throws Exception {
        //base64编码的公钥
        byte[] decoded = Base64.decode(privateKey);
        PrivateKey priKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, priKey);
        //当长度过长的时候，需要分割后加密 117个字节
        byte[] resultBytes = getMaxResultEncrypt(str, cipher);
        return Base64.encode(resultBytes);
    }

    /**
     * RSA公钥解密
     *
     * @param str
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static String publicKeyDecrypt(String str, String publicKey) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decode(str.getBytes("UTF-8"));
        //base64编码的私钥
        byte[] decoded = Base64.decode(publicKey);
        PublicKey pubKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        return new String(getMaxResultDecrypt(str, cipher));
    }

    /**
     * RSA公钥加密
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String publicKeyEncrypt(String str, String publicKey) throws Exception {
        //base64编码的公钥
        byte[] decoded = Base64.decode(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        //当长度过长的时候，需要分割后加密 117个字节
        byte[] resultBytes = getMaxResultEncrypt(str, cipher);
        return Base64.encode(resultBytes);
    }

    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public static String privateKeyDecrypt(String str, String privateKey) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decode(str.getBytes("UTF-8"));
        //base64编码的私钥
        byte[] decoded = Base64.decode(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        //当长度过长的时候，需要分割后解密 128个字节
        return new String(getMaxResultDecrypt(str, cipher));
    }

    private static byte[] getMaxResultEncrypt(String str, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
        byte[] inputArray = str.getBytes();
        int inputLength = inputArray.length;
        // 最大加密字节数，超出最大字节数需要分组加密
        int MAX_ENCRYPT_BLOCK = 117;
        // 标识
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] cache = {};
        while (inputLength - offSet > 0) {
            if (inputLength - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                cache = cipher.doFinal(inputArray, offSet, inputLength - offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
            System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
        }
        return resultBytes;
    }

    private static byte[] getMaxResultDecrypt(String str, Cipher cipher) throws IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException {
        byte[] inputArray = Base64.decode(str.getBytes("UTF-8"));
        int inputLength = inputArray.length;
        // 最大解密字节数，超出最大字节数需要分组加密
        int MAX_ENCRYPT_BLOCK = 128;
        // 标识
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] cache = {};
        while (inputLength - offSet > 0) {
            if (inputLength - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                cache = cipher.doFinal(inputArray, offSet, inputLength - offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
            System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
        }
        return resultBytes;
    }


    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static GisUser encodeRsaToken(String token) {

        GisUser user = new GisUser();
        try {
            token = Base64.encode(hexStringToByteArray(token)) ;
            Object parse = JSONObject.parse(RsaUtils.privateKeyDecrypt(token, PRIVATE_KEY));
            BeanUtil.copyProperties(parse,user);
        } catch (Exception e) {
            e.printStackTrace();
           return null;
        }
        return user;

    }
     private  static String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALKZ/S9rWCiqlaiSoqty6h/EobHrriub2kVYZ5n7lEj3CmIediK5LLSmn7CequdxFlKuPdA22Y9piyxEl9ALb/X/5fNPjJc9zg3DgoJtU6B5QxBa2wWRXhlZUXZ+tA3gckJ3IZoyNeSi3ndLR9UQU4cOriSA7qPHW5PgpaU8xoLNAgMBAAECgYA2yDD2yJBD+P7qs/+dYyQZFnEaZ9YGnkl3F8S/YIF9V/khW4KU6AOkba9xt1looDFerv9azFgzOwZrT6bZM4jlgJEdhKAMMAj+T4B6W8N3bBxBDGRVCYm15uRVhWt2Dqa3R++CsnaamcvKvaz2MRcifuu0GSj0UnVeE/LaScetgQJBAP+eea6hIq/pWNuXhf+l9DW/srsnpHBJVfMxgbM5yTvueLQxinHRBo1qiZFMBAn+iWEG8o+IALMncVZVZhdJSPECQQCy3iEzH6idNhrONWLQrtRVZbQpuyeyH7J0IWCWYqn8myUj0ODI9fuMMICejl+Hf9zFL1hkTwHi2LdE2DqAuTedAkAN6KOaWu42QC4zlKUX6gHFwu6IvHl4GqVwnCsAg45tkmZC98cetk7y9u8RVt+JY64591TPdokDNow2NGNftP8hAkEAqYXPj2WE6CMcOq3sTn40Lg+rNhX0JGTYPCpaIY23L/tWsuBH+w7vbsmVTTEApypu8c/ShZc/4WCmKbCJmfBxHQJAB7TRdWOqXDhPuoKcweK576gSkFc9MDbWayb+nVgV77lqffX4l7Ssif1oilh72MLre9oezL9ngKeqE6Gp/wO2sQ==";


}
