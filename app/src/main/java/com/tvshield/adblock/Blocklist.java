package com.tvshield.adblock;

import android.content.Context;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * База рекламних доменів. Домени зберігаються як відсортований масив 64-бітних хешів:
 * ~300 тис. доменів займають ~2.5 МБ і перевіряються бінарним пошуком за мікросекунди.
 *
 * Джерела (ті самі ідеї, що в Brave / uBlock, але на рівні DNS):
 *  - HaGeZi DNS Blocklists (light / multi / pro)
 *  - AdGuard DNS filter — зібраний з EasyList, EasyPrivacy, AdGuard Base, Mobile Ads,
 *    з винятками @@ (щоб не ламати сайти й додатки)
 *  - Perflyst SmartTV — телеметрія та реклама смарт-ТВ
 */
final class Blocklist {

    static final String[] LEVEL_NAMES = {"Легкий", "Стандарт", "Максимум"};
    private static final String[] HAGEZI = {"light", "multi", "pro"};
    /** Чи додавати AdGuard DNS filter (EasyList/EasyPrivacy) на цьому рівні. */
    private static final boolean[] WITH_ADGUARD = {false, true, true};

    private static final String HAGEZI_RAW =
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/%s-onlydomains.txt";
    private static final String HAGEZI_CDN =
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/%s-onlydomains.txt";
    private static final String ADGUARD_RAW =
            "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/gh-pages/Filters/filter.txt";
    private static final String ADGUARD_CDN =
            "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt";
    private static final String TV_RAW =
            "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt";
    private static final String TV_CDN =
            "https://cdn.jsdelivr.net/gh/Perflyst/PiHoleBlocklist@master/SmartTV.txt";

    /** Те, що ніколи не блокуємо: перевірка інтернету, магазин, YouTube API, оновлення системи. */
    private static final Set<String> NEVER_BLOCK = new HashSet<>(Arrays.asList(
            "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
            "clients3.google.com", "clients4.google.com", "www.google.com",
            "android.clients.google.com", "play.googleapis.com", "android.googleapis.com",
            "www.googleapis.com", "youtubei.googleapis.com", "www.youtube.com", "youtube.com",
            "m.youtube.com", "i.ytimg.com", "googlevideo.com", "time.android.com",
            "mtalk.google.com", "accounts.google.com", "play.google.com"));

    private static final int MAGIC = 0x54565331; // "TVS1"

    private static final Blocklist INSTANCE = new Blocklist();

    static Blocklist get() {
        return INSTANCE;
    }

    private volatile long[] blocked = new long[0];
    private volatile long[] listAllow = new long[0];
    private volatile Set<String> userAllow = Collections.emptySet();
    private volatile int loadedLevel = -1;

    int size() {
        return blocked.length;
    }

    boolean isLoaded() {
        return loadedLevel >= 0;
    }

    // ---------------------------------------------------------------- перевірка

    boolean isBlocked(String name) {
        if (name == null || name.isEmpty()) return false;
        String d = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        if (d.indexOf('.') < 0) return false;            // локальні імена (printer, router)

        long[] b = blocked;
        long[] a = listAllow;
        Set<String> u = userAllow;

        // 1) Винятки мають пріоритет: якщо дозволено домен або його батька — не блокуємо.
        String s = d;
        while (true) {
            if (NEVER_BLOCK.contains(s) || u.contains(s)) return false;
            if (a.length > 0 && Arrays.binarySearch(a, hash(s)) >= 0) return false;
            int dot = s.indexOf('.');
            if (dot < 0) break;
            s = s.substring(dot + 1);
        }
        // 2) Блокуємо, якщо в базі є сам домен або будь-який батьківський.
        s = d;
        while (true) {
            if (Arrays.binarySearch(b, hash(s)) >= 0) return true;
            int dot = s.indexOf('.');
            if (dot < 0) return false;
            s = s.substring(dot + 1);
            if (s.indexOf('.') < 0) return false;        // не блокуємо цілі зони типу "com"
        }
    }

    /** FNV-1a 64 bit. */
    static long hash(String s) {
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < s.length(); i++) {
            h ^= s.charAt(i);
            h *= 0x100000001b3L;
        }
        return h;
    }

    // ---------------------------------------------------------------- завантаження

    synchronized void ensureLoaded(Context ctx) {
        int level = Prefs.level(ctx);
        reloadUserAllow(ctx);
        if (loadedLevel == level && blocked.length > 0) return;
        load(ctx, level);
    }

    synchronized void load(Context ctx, int level) {
        reloadUserAllow(ctx);
        File bin = binFile(ctx, level);
        if (bin.exists()) {
            try {
                readBin(bin);
                loadedLevel = level;
                return;
            } catch (IOException ignored) {
                // зіпсований файл — перебудуємо з вбудованих списків
            }
        }
        try {
            Builder bl = new Builder();
            Builder al = new Builder();
            parse(asset(ctx, HAGEZI[level]), bl, al);
            if (WITH_ADGUARD[level]) parse(asset(ctx, "adguard"), bl, al);
            parse(asset(ctx, "smarttv"), bl, al);
            long[] b = bl.sortedUnique();
            long[] a = al.sortedUnique();
            setData(b, a);
            loadedLevel = level;
            writeBin(bin, b, a);
        } catch (IOException e) {
            setData(new long[0], new long[0]);
            loadedLevel = level;
        }
    }

    void reloadUserAllow(Context ctx) {
        userAllow = new HashSet<>(Prefs.allow(ctx));
    }

    void setData(long[] blockedHashes, long[] allowHashes) {
        listAllow = allowHashes;
        blocked = blockedHashes;
    }

    /** Завантажує свіжі списки з інтернету. Повертає кількість доменів. */
    int update(Context ctx, int level) throws IOException {
        Builder bl = new Builder();
        Builder al = new Builder();
        int main = download(String.format(HAGEZI_RAW, HAGEZI[level]),
                String.format(HAGEZI_CDN, HAGEZI[level]), bl, al);
        if (main < 1000) throw new IOException("Список порожній");
        if (WITH_ADGUARD[level]) {
            try {
                download(ADGUARD_RAW, ADGUARD_CDN, bl, al);
            } catch (IOException ignored) {
                // не критично
            }
        }
        try {
            download(TV_RAW, TV_CDN, bl, al);
        } catch (IOException ignored) {
            // не критично
        }
        long[] b = bl.sortedUnique();
        long[] a = al.sortedUnique();
        synchronized (this) {
            writeBin(binFile(ctx, level), b, a);
            if (Prefs.level(ctx) == level) {
                setData(b, a);
                loadedLevel = level;
            }
        }
        Prefs.setLastUpdate(ctx, System.currentTimeMillis());
        return b.length;
    }

    private static int download(String primary, String mirror, Builder bl, Builder al) throws IOException {
        IOException last = null;
        for (String url : new String[]{primary, mirror}) {
            Builder tb = new Builder();
            Builder ta = new Builder();
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
                c.setConnectTimeout(15000);
                c.setReadTimeout(30000);
                c.setRequestProperty("User-Agent", "TVShield/1.0");
                try {
                    if (c.getResponseCode() != 200) throw new IOException("HTTP " + c.getResponseCode());
                    int n = parse(c.getInputStream(), tb, ta);
                    if (n == 0) throw new IOException("Порожньо");
                    bl.addAll(tb);
                    al.addAll(ta);
                    return n;
                } finally {
                    c.disconnect();
                }
            } catch (IOException e) {
                last = e;
            }
        }
        throw last;
    }

    private static InputStream asset(Context ctx, String name) throws IOException {
        return new GZIPInputStream(ctx.getAssets().open("lists/" + name + ".txt.gz"), 65536);
    }

    /** Розбирає hosts / список доменів / правила Adblock (||domain^, @@||domain^). */
    static int parse(InputStream in, Builder blocked, Builder allowed) throws IOException {
        int count = 0;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8), 65536)) {
            String line;
            while ((line = r.readLine()) != null) {
                boolean exception = line.startsWith("@@");
                String d = parseLine(exception ? line.substring(2) : line);
                if (d == null) continue;
                if (exception) {
                    allowed.add(hash(d));
                } else {
                    blocked.add(hash(d));
                    count++;
                }
            }
        }
        return count;
    }

    static String parseLine(String line) {
        String s = line.trim();
        if (s.isEmpty()) return null;
        char c = s.charAt(0);
        if (c == '#' || c == '!' || c == '[' || c == '/') return null;
        int comment = s.indexOf('#');
        if (comment > 0) s = s.substring(0, comment).trim();

        if (s.startsWith("||")) {
            s = s.substring(2);
            int caret = s.indexOf('^');
            if (caret < 0) return null;
            String tail = s.substring(caret + 1);
            s = s.substring(0, caret);
            // Модифікатори на кшталт $client=, $denyallow= змінюють сенс правила — пропускаємо їх.
            if (tail.startsWith("$") && !tail.equals("$important")) return null;
            if (!tail.isEmpty() && !tail.startsWith("$") && !tail.equals("|")) return null;
        } else {
            int sp = firstSpace(s);
            if (sp > 0) {                                  // формат hosts: "0.0.0.0 domain"
                String rest = s.substring(sp).trim();
                int sp2 = firstSpace(rest);
                s = sp2 > 0 ? rest.substring(0, sp2) : rest;
            }
        }
        if (s.startsWith("*.")) s = s.substring(2);
        if (s.startsWith(".")) s = s.substring(1);
        if (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        if (s.length() < 3 || s.length() > 253 || s.indexOf('.') < 0) return null;
        s = s.toLowerCase(Locale.ROOT);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            boolean ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_';
            if (!ok) return null;                          // *, /, | — шаблони, не домени
        }
        if (s.equals("localhost") || s.equals("localhost.localdomain")) return null;
        return s;
    }

    private static int firstSpace(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == ' ' || ch == '\t') return i;
        }
        return -1;
    }

    // ---------------------------------------------------------------- кеш на диску

    private static File binFile(Context ctx, int level) {
        return new File(ctx.getFilesDir(), "blocklist-" + level + ".bin");
    }

    private static void writeBin(File f, long[] b, long[] a) {
        ByteBuffer buf = ByteBuffer.allocate(12 + 8 * (b.length + a.length));
        buf.putInt(MAGIC).putInt(b.length).putInt(a.length);
        buf.asLongBuffer().put(b).put(a);
        File tmp = new File(f.getPath() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(buf.array());
            out.getFD().sync();
        } catch (IOException e) {
            tmp.delete();
            return;
        }
        if (!tmp.renameTo(f)) tmp.delete();
    }

    private void readBin(File f) throws IOException {
        byte[] data;
        try (InputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream((int) f.length());
            byte[] tmp = new byte[65536];
            int n;
            while ((n = in.read(tmp)) > 0) bos.write(tmp, 0, n);
            data = bos.toByteArray();
        }
        ByteBuffer buf = ByteBuffer.wrap(data);
        if (data.length < 12 || buf.getInt() != MAGIC) throw new IOException("bad file");
        int nb = buf.getInt(), na = buf.getInt();
        if (nb < 0 || na < 0 || data.length != 12 + 8L * (nb + na)) throw new IOException("bad size");
        long[] b = new long[nb], a = new long[na];
        buf.asLongBuffer().get(b).get(a);
        if (nb == 0) throw new IOException("empty");
        setData(b, a);
    }

    // ---------------------------------------------------------------- допоміжне

    static final class Builder {
        private long[] data = new long[1024];
        private int size;

        void add(long v) {
            if (size == data.length) data = Arrays.copyOf(data, size * 2);
            data[size++] = v;
        }

        void addAll(Builder o) {
            for (int i = 0; i < o.size; i++) add(o.data[i]);
        }

        long[] sortedUnique() {
            long[] a = Arrays.copyOf(data, size);
            Arrays.sort(a);
            int w = 0;
            for (int i = 0; i < a.length; i++) {
                if (w == 0 || a[i] != a[w - 1]) a[w++] = a[i];
            }
            return Arrays.copyOf(a, w);
        }
    }
}
