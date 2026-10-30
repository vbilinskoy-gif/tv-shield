package com.tvshield.adblock;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

/** Налаштування додатку. */
final class Prefs {

    static final String[] DNS_NAMES = {
            "Cloudflare (швидкий)",
            "Google",
            "Quad9 (захист від шкідливих сайтів)",
            "AdGuard (+ ще один фільтр реклами)"
    };
    private static final String[][] DNS_SERVERS = {
            {"1.1.1.1", "1.0.0.1"},
            {"8.8.8.8", "8.8.4.4"},
            {"9.9.9.9", "149.112.112.112"},
            {"94.140.14.14", "94.140.15.15"}
    };

    private static final long WEEK = 7L * 24 * 60 * 60 * 1000;

    private Prefs() {}

    private static SharedPreferences sp(Context c) {
        return c.getApplicationContext().getSharedPreferences("tvshield", Context.MODE_PRIVATE);
    }

    static boolean enabled(Context c) { return sp(c).getBoolean("enabled", false); }
    static void setEnabled(Context c, boolean v) { sp(c).edit().putBoolean("enabled", v).apply(); }

    static int level(Context c) {
        int v = sp(c).getInt("level", 1);
        return v < 0 || v >= Blocklist.LEVEL_NAMES.length ? 1 : v;
    }
    static void setLevel(Context c, int v) { sp(c).edit().putInt("level", v).apply(); }

    static int dns(Context c) {
        int v = sp(c).getInt("dns", 0);
        return v < 0 || v >= DNS_SERVERS.length ? 0 : v;
    }
    static void setDns(Context c, int v) { sp(c).edit().putInt("dns", v).apply(); }
    static String[] upstream(Context c) { return DNS_SERVERS[dns(c)]; }

    static long lastUpdate(Context c) { return sp(c).getLong("lastUpdate", 0); }
    static void setLastUpdate(Context c, long t) { sp(c).edit().putLong("lastUpdate", t).apply(); }
    static boolean needsUpdate(Context c) {
        return System.currentTimeMillis() - lastUpdate(c) > WEEK;
    }

    static long lifetimeBlocked(Context c) { return sp(c).getLong("lifetime", 0); }
    static synchronized void addLifetimeBlocked(Context c, long delta) {
        if (delta <= 0) return;
        sp(c).edit().putLong("lifetime", lifetimeBlocked(c) + delta).apply();
    }

    static Set<String> allow(Context c) {
        return new TreeSet<>(sp(c).getStringSet("allow", new HashSet<String>()));
    }
    static synchronized void addAllow(Context c, String domain) {
        Set<String> s = new HashSet<>(allow(c));
        s.add(domain);
        sp(c).edit().putStringSet("allow", s).apply();
    }
    static synchronized void removeAllow(Context c, String domain) {
        Set<String> s = new HashSet<>(allow(c));
        s.remove(domain);
        sp(c).edit().putStringSet("allow", s).apply();
    }
}
