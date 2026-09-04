package com.pif.companion;

import static android.Manifest.permission.READ_CALL_LOG;
import static android.content.pm.PackageManager.PERMISSION_GRANTED;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Process;

/**
 * A pure authority-rewriting relay onto the real system Call Log provider
 * (authority "call_log", see android.provider.CallLog - a stable, unchanged-
 * since-API-1 platform constant). Same design as ContactsProvider in this
 * app, and the same design as github.com/gonodono/adbsms's own
 * AdbSmsProvider: forwards whatever content:// call the shell makes against
 * this app's own exported authority ("pif.companion.calllog") straight
 * through to the real system provider, using this app's own granted
 * permission (READ_CALL_LOG) to authorize the read.
 *
 * checkCallingProcess() restricts every call to SHELL_UID - a co-located
 * app on the device can never use this relay to read the call log itself,
 * even though the provider is exported.
 *
 * Querying content://pif.companion.calllog/calls with no special projection
 * returns every real CallLog.Calls row (number, date, duration, type -
 * incoming/outgoing/missed/etc., name if resolved against a local contact).
 */
public class CallLogProvider extends ContentProvider {

    private static final String REAL_AUTHORITY = "call_log";

    @Override
    public boolean onCreate() {
        return getContext().checkSelfPermission(READ_CALL_LOG) == PERMISSION_GRANTED;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        checkCallingProcess();
        return getContext().getContentResolver().query(toRealUri(uri), projection, selection, selectionArgs, sortOrder);
    }

    @Override
    public String getType(Uri uri) {
        checkCallingProcess();
        return getContext().getContentResolver().getType(toRealUri(uri));
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        checkCallingProcess();
        return getContext().getContentResolver().insert(toRealUri(uri), values);
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        checkCallingProcess();
        return getContext().getContentResolver().delete(toRealUri(uri), selection, selectionArgs);
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        checkCallingProcess();
        return getContext().getContentResolver().update(toRealUri(uri), values, selection, selectionArgs);
    }

    private static void checkCallingProcess() {
        if (Binder.getCallingUid() != Process.SHELL_UID) throw new SecurityException();
    }

    private static Uri toRealUri(Uri uri) {
        return new Uri.Builder()
                .scheme(uri.getScheme())
                .authority(REAL_AUTHORITY)
                .path(uri.getPath())
                .query(uri.getQuery())
                .fragment(uri.getFragment())
                .build();
    }
}
