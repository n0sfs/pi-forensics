package com.pif.companion;

import static android.Manifest.permission.READ_SMS;
import static android.content.pm.PackageManager.PERMISSION_GRANTED;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Process;

/**
 * A pure authority-rewriting relay onto the real system SMS provider
 * (authority "sms", see android.provider.Telephony.Sms). Same design as
 * ContactsProvider/CallLogProvider in this app, and the same design as
 * github.com/gonodono/adbsms's own AdbSmsProvider - the app this SMS
 * capability originally shipped from (2026-09-04) before being folded
 * directly into this app to remove the extra third-party dependency, now
 * that its exact mechanism was already fully understood from reading its
 * real source.
 *
 * Read-only tier: a plain `pm grant READ_SMS` is enough to see this app's
 * own real granted-permission view of the provider (inbox/sent only -
 * Android's own real, documented restriction for any app that isn't the
 * current default SMS app).
 *
 * Full-access tier needs this app to temporarily hold the
 * android.app.role.SMS role (`adb shell cmd role add-role-holder`) to see
 * every folder - the manifest's own SmsReceiver/MmsReceiver/
 * ComposeSmsActivity/HeadlessSmsSendService declarations exist ONLY to
 * satisfy the OS's role-eligibility check for this; none of them are
 * backed by real Java classes, since this app is never actually meant to
 * receive or send real SMS through those paths.
 *
 * checkCallingProcess() restricts every call to SHELL_UID - a co-located
 * app on the device can never use this relay to read SMS itself, even
 * though the provider is exported.
 */
public class SmsProvider extends ContentProvider {

    private static final String REAL_AUTHORITY = "sms";

    @Override
    public boolean onCreate() {
        return getContext().checkSelfPermission(READ_SMS) == PERMISSION_GRANTED;
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
