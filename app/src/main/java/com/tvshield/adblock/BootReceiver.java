package com.tvshield.adblock;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;

/** Автоматично вмикає захист після перезавантаження ТВ або оновлення додатку. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Prefs.enabled(context)) return;
        if (VpnService.prepare(context) != null) return; // дозвіл на VPN відкликано
        try {
            ShieldVpnService.start(context);
        } catch (RuntimeException ignored) {
            // система не дозволила запуск у фоні — користувач увімкне вручну
        }
    }
}
