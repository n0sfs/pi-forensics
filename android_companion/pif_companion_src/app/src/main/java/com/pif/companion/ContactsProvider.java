package com.pif.companion;

import static android.Manifest.permission.READ_CONTACTS;
import static android.content.pm.PackageManager.PERMISSION_GRANTED;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Process;

/**
 * A pure authority-rewriting relay onto the real system Contacts Provider
 * (authority "com.android.contacts", see ContactsContract). Mirrors
 * github.com/gonodono/adbsms's own AdbSmsProvider design exactly - a
 * `content query`/`content insert`/etc. against this app's own exported
 * authority ("pif.companion.contacts") is rewritten to the real system
 * authority and forwarded through this app's own ContentResolver, which
 * runs with this app's own granted permission (READ_CONTACTS), not the
 * calling shell's.
 *
 * checkCallingProcess() restricts every call to SHELL_UID - a co-located
 * app on the device can never use this relay to read contacts itself,
 * even though the provider is exported.
 *
 * The relay preserves the incoming URI's own path/query untouched, so any
 * real ContactsContract sub-path still works unmodified - e.g. querying
 * content://pif.companion.contacts/data with the standard
 * ContactsContract.Data projection returns every contact's phone numbers,
 * emails, and other detail rows (each row's own MIMETYPE column
 * distinguishes the data type), implicitly joined with the contact's own
 * display name - exactly the general-purpose query the official
 * "Retrieve Contact Details" guide documents.
 */
public class ContactsProvider extends ContentProvider {

    private static final String REAL_AUTHORITY = "com.android.contacts";

    @Override
    public boolean onCreate() {
        return getContext().checkSelfPermission(READ_CONTACTS) == PERMISSION_GRANTED;
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
