package com.ztxd.ciphertest;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = MainActivity.class.getSimpleName();
    private String content = "今天我们测试一下AES!!";
    private String encryptStr = null;
    private String decryptStr = null;

    private FingerprintHelper mFingerprintHelper;

    EditText contentEt;
    TextView contentTv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
        mFingerprintHelper = new FingerprintHelper(this);
        mFingerprintHelper.setAuthenticationCallback(callback);
        mFingerprintHelper.generateKey();
    }

    private void initView() {
        contentEt = (EditText) findViewById(R.id.secret_content);
        contentTv = (TextView) findViewById(R.id.decrypt_content);
    }

    //加密
    public void aesEncrypt(View view) {
        if (!TextUtils.isEmpty(contentEt.getText())) {
            content = contentEt.getText().toString();
        }

        mFingerprintHelper.encryptAndAuthenticate(content);
    }

    //解密
    public void aesDecrypt(View view) {
        Log.d("点击解密方法", "encryptStr >>" + encryptStr);
        mFingerprintHelper.decryptAndAuthenticate();
    }

    public void getDefaultType(View view) {

    }


    FingerprintHelper.MyAuthenticationCallback callback = new FingerprintHelper.MyAuthenticationCallback() {
        @Override public void onAuthenticationSucceeded(final String value) {
            MainActivity.this.runOnUiThread(new Runnable() {
                @Override public void run() {
                    contentTv.setText(value);
                }
            });
        }

        @Override public void onAuthenticationFail() {
            Log.e(TAG,"error 认证失败");
        }
    };
}
