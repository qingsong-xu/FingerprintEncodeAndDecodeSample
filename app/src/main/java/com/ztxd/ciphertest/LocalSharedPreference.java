package com.ztxd.ciphertest;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Created by Jack on 2017/9/9.
 */

public class LocalSharedPreference {
    private SharedPreferences mSharedPreferences;

    public LocalSharedPreference(Context context) {
        mSharedPreferences = context.getSharedPreferences("xuqingosng", Context.MODE_PRIVATE);
    }

    protected boolean storeData(String key, String data) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putString(key, data);
        return editor.commit();
    }

    protected String getData(String key) {
        String retVal = mSharedPreferences.getString(key, null);
        return retVal;
    }
}
