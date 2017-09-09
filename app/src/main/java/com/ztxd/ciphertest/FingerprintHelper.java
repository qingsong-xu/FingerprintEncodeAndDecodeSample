package com.ztxd.ciphertest;

/**
 * Created by Jack on 2017/9/9.
 */

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * 实现指纹识别获取密钥，进行数据加解密 1、创建key存入keyStore
 */
public class FingerprintHelper extends FingerprintManager.AuthenticationCallback {
    private static final String TAG =FingerprintHelper.class.getSimpleName();
    public static final String Data_Name = "data";
    public static final String IV_Name = "iv";
    private static final String KeyStoreType = "AndroidKeyStore";
    private static final String KeyStoreAlias = "testKeyStore";
    private Context mContext;
    private KeyStore keyStore;

    private LocalSharedPreference mSharedPreference;
    private FingerprintManager fingerprintManager;
    private CancellationSignal cancellationSignal;
    private MyAuthenticationCallback myAuthenticationCallback;
    private int purpose = KeyProperties.PURPOSE_ENCRYPT;//默认为加密格式
    private String data;

    public FingerprintHelper(Context context) {
        mContext = context;
        mSharedPreference = new LocalSharedPreference(context);
        fingerprintManager = context.getSystemService(FingerprintManager.class);
        cancellationSignal = new CancellationSignal();
    }

    /**
     * 先创建key
     */
    protected void generateKey() {
        try {
            keyStore = KeyStore.getInstance(KeyStoreType);
            keyStore.load(null);

            int purpose = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
            KeyGenParameterSpec.Builder builder =
                new KeyGenParameterSpec.Builder(KeyStoreAlias, purpose);
            builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC);
            builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);
            builder.setUserAuthenticationRequired(true);
            KeyGenParameterSpec spec = builder.build();

            KeyGenerator generator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KeyStoreType);
            generator.init(spec);
            generator.generateKey();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    protected void setAuthenticationCallback(MyAuthenticationCallback callback) {
        this.myAuthenticationCallback = callback;
    }

    /**
     * 指纹认证，进行加密
     */
    protected void decryptAndAuthenticate() {
        FingerprintManager.CryptoObject cryptoObject;
        String iv = mSharedPreference.getData(IV_Name);
        byte[] IV = Base64.decode(iv,Base64.DEFAULT);

        purpose = KeyProperties.PURPOSE_DECRYPT;

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KeyStoreAlias, null);
            if (key == null) {
                return;
            }

            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES
                + "/"
                + KeyProperties.BLOCK_MODE_CBC
                + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipher.init(KeyProperties.PURPOSE_DECRYPT, key,new IvParameterSpec(IV));

            cryptoObject = new FingerprintManager.CryptoObject(cipher);
            if (cryptoObject == null){
                return;
            }
            if (ActivityCompat.checkSelfPermission(mContext, Manifest.permission.USE_FINGERPRINT)
                != PackageManager.PERMISSION_GRANTED) {
                // TODO: Consider calling
                return;
            }

            fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    /**
     * 指纹认证，进行解密
     */
    protected void encryptAndAuthenticate(String encryptStr) {
        purpose = KeyProperties.PURPOSE_ENCRYPT;
        data = encryptStr;
        FingerprintManager.CryptoObject cryptoObject;
        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KeyStoreAlias, null);
            if (key == null) {
                return;
            }

            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES
                + "/"
                + KeyProperties.BLOCK_MODE_CBC
                + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipher.init(KeyProperties.PURPOSE_ENCRYPT, key);

            cryptoObject = new FingerprintManager.CryptoObject(cipher);

            if (ActivityCompat.checkSelfPermission(mContext, Manifest.permission.USE_FINGERPRINT)
                != PackageManager.PERMISSION_GRANTED) {
                Log.e("hehe","没权限");
                return;
            }

            fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    @Override public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
        Log.e(TAG,errorCode+":"+errString);
        myAuthenticationCallback.onAuthenticationFail();
    }

    @Override public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);
        Log.e(TAG,helpCode+":"+helpString);
        myAuthenticationCallback.onAuthenticationFail();
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        if (myAuthenticationCallback == null) {
            return;
        }

        if (result.getCryptoObject() == null) {
            return;
        }

        Cipher cipher = result.getCryptoObject().getCipher();
        if (purpose == KeyProperties.PURPOSE_ENCRYPT) {//加密情景下
            try {
                byte[] encryptByte = cipher.doFinal(data.getBytes());
                byte[] IV = cipher.getIV();

                String se = Base64.encodeToString(encryptByte, Base64.DEFAULT);
                String siv = Base64.encodeToString(IV, Base64.DEFAULT);
                Log.d("加密认证》》", "se = " + se + " siv = " + siv);

                if (mSharedPreference.storeData(Data_Name, se) && mSharedPreference.storeData(
                    IV_Name, siv)) {
                    myAuthenticationCallback.onAuthenticationSucceeded(se);
                } else {
                    myAuthenticationCallback.onAuthenticationFail();
                }
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
                myAuthenticationCallback.onAuthenticationFail();
            } catch (BadPaddingException e) {
                e.printStackTrace();
                myAuthenticationCallback.onAuthenticationFail();
            }
        } else if (purpose == KeyProperties.PURPOSE_DECRYPT) {//解密
            //取出secret key并返回
            String data = mSharedPreference.getData(Data_Name);
            if (TextUtils.isEmpty(data)) {
                return;
            }

            try {
                byte[] decodVal = cipher.doFinal(Base64.decode(data, Base64.DEFAULT));
                myAuthenticationCallback.onAuthenticationSucceeded(new String(decodVal));
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            }
        }
    }

    @Override public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        myAuthenticationCallback.onAuthenticationFail();
    }

    public interface MyAuthenticationCallback {
        void onAuthenticationSucceeded(String value);

        void onAuthenticationFail();
    }
}
