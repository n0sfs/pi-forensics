package com.pif.companion;

import static android.Manifest.permission.READ_EXTERNAL_STORAGE;
import static android.Manifest.permission.READ_MEDIA_IMAGES;
import static android.Manifest.permission.READ_MEDIA_VIDEO;
import static android.content.pm.PackageManager.PERMISSION_GRANTED;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Process;

/**
 * A pure authority-rewriting relay onto the real system Media Provider
 * (authority "media", see MediaStore.AUTHORITY - confirmed live via the
 * real API reference, not guessed). Mirrors ContactsProvider/
 * CallLogProvider/SmsProvider/CalendarProvider exactly - a `content
 * query`/`content insert`/etc. against this app's own exported authority
 * ("pif.companion.media") is rewritten to the real system authority and
 * forwarded through this app's own ContentResolver, which runs with this
 * app's own granted permission, not the calling shell's.
 *
 * checkCallingProcess() restricts every call to SHELL_UID - a co-located
 * app on the device can never use this relay to read media itself, even
 * though the provider is exported.
 *
 * onCreate() checks any ONE of the three possible media-read permissions
 * being granted (READ_MEDIA_IMAGES/READ_MEDIA_VIDEO on Android 13+,
 * READ_EXTERNAL_STORAGE on older devices) rather than requiring a single
 * fixed one - the caller (routes/mobile.py) attempts to grant all three
 * independently and treats each grant's own success/failure as non-fatal,
 * since which one actually exists/matters depends on the connected
 * device's own Android version.
 *
 * The relay preserves the incoming URI's own path/query untouched, so
 * both content://pif.companion.media/external/images/media and
 * content://pif.companion.media/external/video/media work unmodified
 * under this one shared authority, exactly like CalendarProvider already
 * serves both its own events/attendees sub-paths.
 */
public class MediaProvider extends ContentProvider {

    private static final String REAL_AUTHORITY = "media";

    @Override
    public boolean onCreate() {
        Context ctx = getContext();
        return ctx.checkSelfPermission(READ_MEDIA_IMAGES) == PERMISSION_GRANTED
                || ctx.checkSelfPermission(READ_MEDIA_VIDEO) == PERMISSION_GRANTED
                || ctx.checkSelfPermission(READ_EXTERNAL_STORAGE) == PERMISSION_GRANTED;
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
