package com.tvshield.adblock;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * "DNS-only" VPN: через тунель іде ЛИШЕ трафік на наш віртуальний DNS-сервер.
 * Відео, ігри та все інше йде напряму, тому швидкість інтернету не страждає.
 * Запити до рекламних доменів отримують 0.0.0.0, решта пересилається справжньому DNS.
 */
public class ShieldVpnService extends VpnService implements Runnable {

    static final String ACTION_START = "com.tvshield.adblock.START";
    static final String ACTION_STOP = "com.tvshield.adblock.STOP";

    private static final String VPN_ADDRESS = "10.111.222.1";
    private static final String DNS_ADDRESS = "10.111.222.2";
    private static final String CHANNEL = "shield";
    private static final int NOTIFICATION_ID = 1;
    private static final int RECENT_MAX = 60;
    private static final long SAVE_EVERY_MS = 30_000;
    private static final long UPDATE_CHECK_EVERY_MS = 6L * 60 * 60 * 1000;

    // Стан для екрана (той самий процес).
    static volatile boolean running;
    static volatile String lastError;
    static final AtomicLong totalQueries = new AtomicLong();
    static final AtomicLong blockedQueries = new AtomicLong();
    static final AtomicLong unsavedBlocked = new AtomicLong();
    private static final ArrayDeque<String> RECENT = new ArrayDeque<>();
    static volatile int recentVersion;

    private volatile boolean stopping;
    private Thread worker;
    private ParcelFileDescriptor tun;
    private FileDescriptor tunFd;
    private ExecutorService pool;
    private final Object writeLock = new Object();

    // ---------------------------------------------------------------- життєвий цикл

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            Prefs.setEnabled(this, false);
            shutdown();
            stopForegroundCompat();
            stopSelf();
            return START_NOT_STICKY;
        }
        startForegroundCompat();
        synchronized (this) {
            if (worker == null || !worker.isAlive()) {
                stopping = false;
                lastError = null;
                pool = Executors.newFixedThreadPool(24);
                worker = new Thread(this, "TVShield-DNS");
                worker.start();
            }
        }
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        // Інший VPN забрав тунель або користувач вимкнув у налаштуваннях.
        Prefs.setEnabled(this, false);
        shutdown();
        stopForegroundCompat();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }

    private void shutdown() {
        stopping = true;
        Thread w;
        synchronized (this) {
            w = worker;
            worker = null;
        }
        if (w != null) {
            try {
                w.join(3000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        closeTun();
        ExecutorService p = pool;
        if (p != null) p.shutdownNow();
        Prefs.addLifetimeBlocked(this, unsavedBlocked.getAndSet(0));
        running = false;
    }

    private synchronized void closeTun() {
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
            }
            tun = null;
            tunFd = null;
        }
    }

    // ---------------------------------------------------------------- головний цикл

    @Override
    public void run() {
        try {
            Blocklist.get().ensureLoaded(this);
            if (stopping) return;
            maybeAutoUpdate();

            Builder b = new Builder();
            b.setSession("TV Щит");
            b.addAddress(VPN_ADDRESS, 32);
            b.addRoute(DNS_ADDRESS, 32);
            b.addDnsServer(DNS_ADDRESS);
            b.setMtu(1500);
            b.setBlocking(false);
            b.allowFamily(OsConstants.AF_INET6);       // IPv6 іде напряму, не блокується
            try {
                b.addDisallowedApplication(getPackageName()); // наш додаток — без тунелю
            } catch (PackageManager.NameNotFoundException ignored) {
            }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false); // щоб стрімінг не знижував якість
            b.setConfigureIntent(PendingIntent.getActivity(this, 0,
                    new Intent(this, MainActivity.class), pendingFlags()));

            ParcelFileDescriptor pfd = b.establish();
            if (pfd == null) {
                lastError = "Немає дозволу на VPN";
                Prefs.setEnabled(this, false);
                stopSelf();
                return;
            }
            synchronized (this) {
                tun = pfd;
                tunFd = pfd.getFileDescriptor();
            }
            running = true;
            loop(tunFd);
        } catch (Exception e) {
            lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            running = false;
            closeTun();
        }
    }

    private void loop(FileDescriptor fd) throws ErrnoException {
        byte[] buf = new byte[32767];
        StructPollfd pfd = new StructPollfd();
        pfd.fd = fd;
        pfd.events = (short) OsConstants.POLLIN;
        StructPollfd[] fds = {pfd};
        long lastSave = System.currentTimeMillis();
        long lastUpdateCheck = lastSave;

        while (!stopping) {
            pfd.revents = 0;
            int ready;
            try {
                ready = Os.poll(fds, 1000);
            } catch (ErrnoException e) {
                if (e.errno == OsConstants.EINTR) continue;
                throw e;
            }
            long now = System.currentTimeMillis();
            if (now - lastSave > SAVE_EVERY_MS) {
                Prefs.addLifetimeBlocked(this, unsavedBlocked.getAndSet(0));
                lastSave = now;
            }
            if (now - lastUpdateCheck > UPDATE_CHECK_EVERY_MS) {
                maybeAutoUpdate();
                lastUpdateCheck = now;
            }
            if (ready <= 0) continue;
            if ((pfd.revents & (OsConstants.POLLERR | OsConstants.POLLHUP | OsConstants.POLLNVAL)) != 0) break;
            if ((pfd.revents & OsConstants.POLLIN) == 0) continue;

            int n;
            try {
                n = Os.read(fd, buf, 0, buf.length);
            } catch (ErrnoException e) {
                if (e.errno == OsConstants.EAGAIN || e.errno == OsConstants.EINTR) continue;
                throw e;
            } catch (java.io.InterruptedIOException e) {
                continue;
            }
            if (n > 0) handlePacket(buf, n);
        }
    }

    private void handlePacket(byte[] buf, int n) {
        Dns.Query q = Dns.parse(buf, n);
        if (q == null) return;
        totalQueries.incrementAndGet();

        if (q.name != null && q.questionEnd > 0 && Blocklist.get().isBlocked(q.name)) {
            blockedQueries.incrementAndGet();
            unsavedBlocked.incrementAndGet();
            addRecent(q.name);
            write(Dns.blockedResponse(buf, q));
            return;
        }
        final byte[] payload = Arrays.copyOfRange(buf, q.dnsOffset, q.dnsOffset + q.dnsLength);
        try {
            pool.execute(() -> forward(q, payload));
        } catch (RejectedExecutionException ignored) {
            // сервіс зупиняється
        }
    }

    /** Пересилає запит справжньому DNS (основний, потім резервний). */
    private void forward(Dns.Query q, byte[] payload) {
        for (String host : Prefs.upstream(this)) {
            if (stopping) return;
            try (DatagramSocket s = new DatagramSocket()) {
                protect(s);
                s.setSoTimeout(2500);
                InetAddress addr = InetAddress.getByName(host);
                s.send(new DatagramPacket(payload, payload.length, addr, 53));
                byte[] rb = new byte[4096];
                DatagramPacket rp = new DatagramPacket(rb, rb.length);
                while (true) {
                    s.receive(rp);
                    // Відповідь має мати той самий ID транзакції
                    if (rp.getLength() >= 12 && rb[0] == payload[0] && rb[1] == payload[1]) break;
                    rp.setLength(rb.length);
                }
                write(Dns.wrap(q, rb, rp.getLength()));
                return;
            } catch (IOException ignored) {
                // пробуємо наступний сервер
            }
        }
    }

    private void write(byte[] packet) {
        synchronized (writeLock) {
            FileDescriptor fd = tunFd;
            if (fd == null) return;
            try {
                Os.write(fd, packet, 0, packet.length);
            } catch (ErrnoException | java.io.InterruptedIOException ignored) {
                // черга тунелю переповнена або закрита — пакет губиться, застосунок перепитає
            }
        }
    }

    private void maybeAutoUpdate() {
        if (!Prefs.needsUpdate(this)) return;
        final Context ctx = getApplicationContext();
        Thread t = new Thread(() -> {
            try {
                Blocklist.get().update(ctx, Prefs.level(ctx));
            } catch (Exception ignored) {
                // спробуємо пізніше
            }
        }, "TVShield-update");
        t.setPriority(Thread.MIN_PRIORITY);
        t.start();
    }

    // ---------------------------------------------------------------- список останніх

    private static void addRecent(String name) {
        synchronized (RECENT) {
            if (name.equals(RECENT.peekFirst())) return;
            RECENT.remove(name);
            RECENT.addFirst(name);
            while (RECENT.size() > RECENT_MAX) RECENT.removeLast();
            recentVersion++;
        }
    }

    static List<String> recentSnapshot() {
        synchronized (RECENT) {
            return new ArrayList<>(RECENT);
        }
    }

    static void forgetRecent(String name) {
        synchronized (RECENT) {
            if (RECENT.remove(name)) recentVersion++;
        }
    }

    // ---------------------------------------------------------------- сповіщення

    private void startForegroundCompat() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "Захист від реклами",
                    NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
            nb = new Notification.Builder(this, CHANNEL);
        } else {
            nb = new Notification.Builder(this);
        }
        Intent stop = new Intent(this, ShieldVpnService.class).setAction(ACTION_STOP);
        nb.setSmallIcon(android.R.drawable.ic_secure)
                .setContentTitle("TV Щит працює")
                .setContentText("Реклама і стеження блокуються")
                .setOngoing(true)
                .setContentIntent(PendingIntent.getActivity(this, 0,
                        new Intent(this, MainActivity.class), pendingFlags()))
                .addAction(new Notification.Action.Builder(0, "Вимкнути",
                        PendingIntent.getService(this, 1, stop, pendingFlags())).build());
        Notification n = nb.build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, n);
        }
    }

    @SuppressWarnings("deprecation")
    private void stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
    }

    static int pendingFlags() {
        return PendingIntent.FLAG_UPDATE_CURRENT
                | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
    }

    static void start(Context c) {
        Intent i = new Intent(c, ShieldVpnService.class).setAction(ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) {
            c.startForegroundService(i);
        } else {
            c.startService(i);
        }
    }

    static void stop(Context c) {
        c.startService(new Intent(c, ShieldVpnService.class).setAction(ACTION_STOP));
    }
}
