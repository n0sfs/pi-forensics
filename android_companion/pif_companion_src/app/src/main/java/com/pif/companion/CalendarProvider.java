package com.pif.companion;

import static android.Manifest.permission.READ_CALENDAR;
import static android.content.pm.PackageManager.PERMISSION_GRANTED;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Process;

/**
 * A pure authority-rewriting relay onto the real system Calendar Provider
 * (authority "com.android.calendar", see CalendarContract). Mirrors
 * ContactsProvider/CallLogProvider/SmsProvider exactly - a `content
 * query`/`content insert`/etc. against this app's own exported authority
 * ("pif.companion.calendar") is rewritten to the real system authority and
 * forwarded through this app's own ContentResolver, which runs with this
 * app's own granted permission (READ_CALENDAR), not the calling shell's.
 *
 * checkCallingProcess() restricts every call to SHELL_UID - a co-located
 * app on the device can never use this relay to read calendar data itself,
 * even though the provider is exported.
 *
 * The relay preserves the incoming URI's own path/query untouched, so both
 * real CalendarContract sub-paths this app's own Python side queries still
 * work unmodified - content://pif.companion.calendar/events (event
 * details: title, time, location, organizer, recurrence rule) and
 * content://pif.companion.calendar/attendees (who was invited to each
 * event and their own RSVP status), both under the identical "com.android.
 * calendar" authority CalendarContract itself uses for every one of its
 * sub-tables.
 */
public class CalendarProvider extends ContentProvider {

    private static final String REAL_AUTHORITY = "com.android.calendar";

    @Override
    public boolean onCreate() {
        return getContext().checkSelfPermission(READ_CALENDAR) == PERMISSION_GRANTED;
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
