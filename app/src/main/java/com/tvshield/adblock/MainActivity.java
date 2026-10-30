package com.tvshield.adblock;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** Головний екран. Інтерфейс зроблено під пульт: великі кнопки, чітке підсвічування фокусу. */
public class MainActivity extends Activity {

    private static final int REQ_VPN = 10;

    private static final int BG = 0xFF0E141B;
    private static final int CARD = 0xFF1A2430;
    private static final int CARD_FOCUS = 0xFF2B3B4F;
    private static final int TEXT = 0xFFE8EEF4;
    private static final int MUTED = 0xFF8A99AA;
    private static final int GREEN = 0xFF2ECC71;
    private static final int RED = 0xFFE5534B;
    private static final int ACCENT = 0xFF4DA3FF;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView status, stats, emptyView;
    private Button toggle, levelBtn, dnsBtn, updateBtn, allowBtn;
    private ArrayAdapter<String> adapter;
    private int shownRecentVersion = -1;
    private boolean busy;

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().getDecorView().setBackgroundColor(BG);
        setContentView(buildUi());

        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2);
        }
        new Thread(() -> {
            Blocklist.get().ensureLoaded(getApplicationContext());
            handler.post(this::refresh);
        }, "TVShield-load").start();
        toggle.requestFocus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(tick);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(tick);
        super.onPause();
    }

    // ---------------------------------------------------------------- інтерфейс

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.HORIZONTAL);
        root.setPadding(dp(48), dp(27), dp(48), dp(27)); // безпечна зона ТВ (overscan)

        // Ліва колонка: статус і кнопки
        LinearLayout left = new LinearLayout(this);
        left.setOrientation(LinearLayout.VERTICAL);
        left.setPadding(0, 0, dp(24), 0);

        TextView title = text("🛡  TV Щит", 30, TEXT);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        left.addView(title);

        status = text("", 20, GREEN);
        status.setTypeface(Typeface.DEFAULT_BOLD);
        status.setPadding(0, dp(8), 0, dp(4));
        left.addView(status);

        stats = text("", 15, MUTED);
        stats.setPadding(0, 0, 0, dp(8));
        left.addView(stats);

        toggle = button("", v -> onToggle());
        levelBtn = button("", v -> onLevel());
        dnsBtn = button("", v -> onDns());
        updateBtn = button("Оновити списки реклами", v -> onUpdate());
        allowBtn = button("", v -> onAllowList());
        Button yt = button("YouTube без реклами — як?", v -> onYoutube());
        for (View b : new View[]{toggle, levelBtn, dnsBtn, updateBtn, allowBtn, yt}) left.addView(b);

        ScrollView leftScroll = new ScrollView(this);
        leftScroll.setVerticalScrollBarEnabled(false);
        leftScroll.addView(left);
        root.addView(leftScroll, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f));

        // Права колонка: що заблоковано щойно
        LinearLayout right = new LinearLayout(this);
        right.setOrientation(LinearLayout.VERTICAL);
        right.setPadding(dp(20), dp(16), dp(20), dp(16));
        right.setBackground(round(CARD, 0, 0));

        TextView header = text("Щойно заблоковано", 20, TEXT);
        header.setTypeface(Typeface.DEFAULT_BOLD);
        right.addView(header);
        TextView hint = text("Якщо щось перестало працювати — вибери домен і натисни ОК, щоб дозволити його.", 13, MUTED);
        hint.setPadding(0, dp(4), 0, dp(10));
        right.addView(hint);

        emptyView = text("Поки нічого. Увімкни захист і відкрий будь-який додаток.", 15, MUTED);
        emptyView.setPadding(0, dp(12), 0, 0);
        right.addView(emptyView);

        ListView list = new ListView(this);
        list.setDivider(null);
        list.setSelector(focusable(0x00000000, CARD_FOCUS, 0));
        list.setDrawSelectorOnTop(false);
        list.setItemsCanFocus(false);
        adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, new ArrayList<String>()) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                TextView tv = (TextView) super.getView(position, convertView, parent);
                tv.setTextColor(TEXT);
                tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
                tv.setPadding(dp(12), dp(8), dp(12), dp(8));
                tv.setSingleLine(true);
                return tv;
            }
        };
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, position, id) -> confirmAllow(adapter.getItem(position)));
        right.addView(list, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        root.addView(right, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1.1f));
        return root;
    }

    private void refresh() {
        boolean on = ShieldVpnService.running;
        status.setText(on ? "● Захист увімкнено" : "○ Захист вимкнено");
        status.setTextColor(on ? GREEN : RED);
        toggle.setText(on ? "Вимкнути захист" : "Увімкнути захист");

        long total = ShieldVpnService.totalQueries.get();
        long blocked = ShieldVpnService.blockedQueries.get();
        long lifetime = Prefs.lifetimeBlocked(this) + ShieldVpnService.unsavedBlocked.get();
        StringBuilder sb = new StringBuilder();
        if (on) {
            int pct = total == 0 ? 0 : (int) (blocked * 100 / total);
            sb.append(String.format(Locale.getDefault(), "Зараз: %,d запитів, заблоковано %,d (%d%%)\n", total, blocked, pct));
        } else if (ShieldVpnService.lastError != null) {
            sb.append("Помилка: ").append(ShieldVpnService.lastError).append('\n');
        }
        sb.append(String.format(Locale.getDefault(), "Усього заблоковано: %,d\n", lifetime));
        int size = Blocklist.get().size();
        long upd = Prefs.lastUpdate(this);
        sb.append(size == 0 ? "Завантажую базу…"
                : String.format(Locale.getDefault(), "У базі %,d доменів · %s", size,
                upd == 0 ? "вбудована версія" : "оновлено " + DateFormat.getDateInstance(DateFormat.SHORT).format(new Date(upd))));
        stats.setText(sb.toString());

        levelBtn.setText("Рівень захисту: " + Blocklist.LEVEL_NAMES[Prefs.level(this)]);
        dnsBtn.setText("DNS: " + Prefs.DNS_NAMES[Prefs.dns(this)]);
        allowBtn.setText("Дозволені домени (" + Prefs.allow(this).size() + ")");
        if (!busy) updateBtn.setText("Оновити списки реклами");

        int v = ShieldVpnService.recentVersion;
        if (v != shownRecentVersion) {
            shownRecentVersion = v;
            List<String> items = ShieldVpnService.recentSnapshot();
            adapter.clear();
            adapter.addAll(items);
            emptyView.setVisibility(items.isEmpty() ? View.VISIBLE : View.GONE);
        }
    }

    // ---------------------------------------------------------------- дії

    private void onToggle() {
        if (ShieldVpnService.running) {
            ShieldVpnService.stop(this);
            Prefs.setEnabled(this, false);
            handler.postDelayed(this::refresh, 400);
            return;
        }
        Intent consent;
        try {
            consent = VpnService.prepare(this);
        } catch (RuntimeException e) {
            consent = null;
        }
        if (consent == null) {
            onActivityResult(REQ_VPN, RESULT_OK, null);
            return;
        }
        try {
            startActivityForResult(consent, REQ_VPN);
        } catch (ActivityNotFoundException e) {
            showNoVpnSupport();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_VPN) return;
        if (resultCode == RESULT_OK) {
            Prefs.setEnabled(this, true);
            ShieldVpnService.start(this);
            toast("Захист увімкнено. Додатки, які вже були відкриті, краще перезапустити.");
            handler.postDelayed(this::refresh, 800);
        } else {
            toast("Без дозволу на VPN блокування не працюватиме.");
        }
    }

    private void onLevel() {
        if (busy) return;
        final int next = (Prefs.level(this) + 1) % Blocklist.LEVEL_NAMES.length;
        Prefs.setLevel(this, next);
        busy = true;
        levelBtn.setText("Рівень захисту: " + Blocklist.LEVEL_NAMES[next] + " (завантаження…)");
        new Thread(() -> {
            Blocklist.get().load(getApplicationContext(), next);
            handler.post(() -> {
                busy = false;
                refresh();
                String[] desc = {
                        "Легкий: мінімум блокувань, нічого не зламається.",
                        "Стандарт: як у Brave — EasyList, EasyPrivacy, AdGuard. Рекомендовано.",
                        "Максимум: блокує агресивно, зрідка щось може не відкритися."};
                toast(desc[next]);
            });
        }, "TVShield-level").start();
    }

    private void onDns() {
        int next = (Prefs.dns(this) + 1) % Prefs.DNS_NAMES.length;
        Prefs.setDns(this, next);
        refresh();
    }

    private void onUpdate() {
        if (busy) return;
        busy = true;
        updateBtn.setText("Оновлюю… (до хвилини)");
        final int level = Prefs.level(this);
        new Thread(() -> {
            String msg;
            try {
                int n = Blocklist.get().update(getApplicationContext(), level);
                msg = String.format(Locale.getDefault(), "Готово! У базі %,d рекламних доменів.", n);
            } catch (Exception e) {
                msg = "Не вдалося оновити. Перевір інтернет і спробуй ще раз.";
            }
            final String m = msg;
            handler.post(() -> {
                busy = false;
                refresh();
                toast(m);
            });
        }, "TVShield-update").start();
    }

    private void confirmAllow(final String domain) {
        if (domain == null) return;
        dialog().setTitle("Дозволити домен?")
                .setMessage(domain + "\n\nВін більше не блокуватиметься. Використовуй, якщо через блокування щось перестало працювати.")
                .setPositiveButton("Дозволити", (d, w) -> {
                    Prefs.addAllow(this, domain);
                    Blocklist.get().reloadUserAllow(this);
                    ShieldVpnService.forgetRecent(domain);
                    refresh();
                    toast("Дозволено. Перезапусти додаток, якщо він ще не працює.");
                })
                .setNegativeButton("Скасувати", null)
                .show();
    }

    private void onAllowList() {
        final List<String> items = new ArrayList<>(Prefs.allow(this));
        if (items.isEmpty()) {
            dialog().setTitle("Дозволені домени")
                    .setMessage("Список порожній. Додати домен можна зі списку «Щойно заблоковано» праворуч.")
                    .setPositiveButton("OK", null)
                    .show();
            return;
        }
        dialog().setTitle("Вибери домен, щоб знову його блокувати")
                .setItems(items.toArray(new String[0]), (d, which) -> {
                    Prefs.removeAllow(this, items.get(which));
                    Blocklist.get().reloadUserAllow(this);
                    refresh();
                    toast("Домен знову блокується.");
                })
                .setNegativeButton("Закрити", null)
                .show();
    }

    private void onYoutube() {
        dialog().setTitle("Реклама в YouTube")
                .setMessage("Офіційний YouTube показує рекламу з тих самих серверів, що й відео, тому її не "
                        + "може заблокувати жоден DNS-блокувальник — ні цей, ні AdGuard, ні Pi-hole.\n\n"
                        + "Brave прибирає її інакше: змінює код самої сторінки в браузері. На телевізорі так "
                        + "само працює безкоштовний відкритий клієнт SmartTube: без реклами, з пропуском "
                        + "спонсорських вставок, з входом у твій акаунт.\n\n"
                        + "Як встановити: додаток Downloader → код 28544 (або адреса kutt.it/stn_stable). "
                        + "Не качай SmartTube з магазинів і APK-сайтів — там бувають підробки.")
                .setPositiveButton("Зрозуміло", null)
                .show();
    }

    private void showNoVpnSupport() {
        dialog().setTitle("Телевізор не підтримує VPN-додатки")
                .setMessage("Виробник прибрав системне вікно дозволу VPN. Тоді найкраще працює блокування "
                        + "через DNS у налаштуваннях мережі: Налаштування → Мережа → Приватний DNS → "
                        + "dns.adguard-dns.com. Або вкажи DNS 94.140.14.14 у роутері — тоді реклама "
                        + "зникне на всіх пристроях удома.")
                .setPositiveButton("OK", null)
                .show();
    }

    // ---------------------------------------------------------------- допоміжне

    private AlertDialog.Builder dialog() {
        return new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert);
    }

    private Button button(String label, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextColor(TEXT);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 17);
        b.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
        b.setPadding(dp(20), dp(12), dp(20), dp(12));
        b.setBackground(focusable(CARD, CARD_FOCUS, ACCENT));
        b.setStateListAnimator(null);
        b.setFocusable(true);
        b.setOnClickListener(l);
        b.setOnFocusChangeListener((v, has) ->
                v.animate().scaleX(has ? 1.03f : 1f).scaleY(has ? 1.03f : 1f).setDuration(120).start());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(10);
        lp.leftMargin = dp(6);
        lp.rightMargin = dp(6);
        b.setLayoutParams(lp);
        return b;
    }

    private StateListDrawable focusable(int normal, int focused, int stroke) {
        StateListDrawable s = new StateListDrawable();
        GradientDrawable f = round(focused, stroke == 0 ? 0 : dp(3), stroke == 0 ? Color.WHITE : stroke);
        s.addState(new int[]{android.R.attr.state_focused}, f);
        s.addState(new int[]{android.R.attr.state_pressed}, f);
        s.addState(new int[]{android.R.attr.state_selected}, f);
        s.addState(new int[]{}, round(normal, 0, 0));
        return s;
    }

    private GradientDrawable round(int color, int strokeWidth, int strokeColor) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(12));
        if (strokeWidth > 0) g.setStroke(strokeWidth, strokeColor);
        return g;
    }

    private TextView text(String s, int sp, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        return t;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }
}
