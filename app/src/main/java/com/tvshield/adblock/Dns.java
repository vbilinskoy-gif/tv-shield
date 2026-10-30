package com.tvshield.adblock;

/**
 * Мінімальний розбір і побудова DNS-пакетів (IPv4 + UDP), які приходять у VPN-тунель.
 * Чиста Java, без залежностей від Android — тому легко тестується.
 */
final class Dns {
    static final int TYPE_A = 1;
    static final int TYPE_AAAA = 28;
    /** TTL для заблокованих відповідей: коротко, щоб "Дозволити" спрацьовувало швидко. */
    private static final int BLOCKED_TTL = 60;

    static final class Query {
        int ipHeaderLen;
        final byte[] srcIp = new byte[4];
        final byte[] dstIp = new byte[4];
        int srcPort;
        int dstPort;
        int dnsOffset;
        int dnsLength;
        /** Доменне ім'я в нижньому регістрі; null, якщо не вдалося розібрати. */
        String name;
        int qtype;
        /** Абсолютний зсув у пакеті одразу після QTYPE/QCLASS. */
        int questionEnd;
    }

    private static int ipId;

    private Dns() {}

    /** Повертає null, якщо це не DNS-запит IPv4/UDP на порт 53. */
    static Query parse(byte[] p, int len) {
        if (len < 28) return null;
        if (((p[0] >> 4) & 0x0F) != 4) return null;
        int ihl = (p[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl + 8) return null;
        if ((p[9] & 0xFF) != 17) return null;            // тільки UDP
        if ((u16(p, 6) & 0x3FFF) != 0) return null;      // фрагменти не обробляємо
        int totalLen = Math.min(u16(p, 2), len);
        if (totalLen < ihl + 8) return null;

        Query q = new Query();
        q.ipHeaderLen = ihl;
        System.arraycopy(p, 12, q.srcIp, 0, 4);
        System.arraycopy(p, 16, q.dstIp, 0, 4);
        q.srcPort = u16(p, ihl);
        q.dstPort = u16(p, ihl + 2);
        if (q.dstPort != 53) return null;
        int udpLen = u16(p, ihl + 4);
        q.dnsOffset = ihl + 8;
        q.dnsLength = Math.min(udpLen - 8, totalLen - ihl - 8);
        if (q.dnsLength < 12) return null;

        int end = q.dnsOffset + q.dnsLength;
        if (u16(p, q.dnsOffset + 4) < 1) return q;       // немає питання — просто перешлемо

        StringBuilder sb = new StringBuilder(64);
        int i = q.dnsOffset + 12;
        while (true) {
            if (i >= end) return q;
            int l = p[i] & 0xFF;
            if (l == 0) { i++; break; }
            if ((l & 0xC0) != 0) return q;               // стиснення в запиті — не очікуємо
            if (i + 1 + l > end || sb.length() + l + 1 > 255) return q;
            if (sb.length() > 0) sb.append('.');
            for (int k = 1; k <= l; k++) {
                char c = (char) (p[i + k] & 0xFF);
                if (c >= 'A' && c <= 'Z') c = (char) (c + 32);
                sb.append(c);
            }
            i += 1 + l;
        }
        if (i + 4 > end) return q;
        q.qtype = u16(p, i);
        q.questionEnd = i + 4;
        q.name = sb.toString();
        return q;
    }

    /** Відповідь "домену не існує по суті": A → 0.0.0.0, AAAA → ::, інші типи → порожня відповідь. */
    static byte[] blockedResponse(byte[] p, Query q) {
        int o = q.dnsOffset;
        int qLen = q.questionEnd - (o + 12);
        boolean answer = q.qtype == TYPE_A || q.qtype == TYPE_AAAA;
        int rdLen = q.qtype == TYPE_AAAA ? 16 : 4;
        int dnsLen = 12 + qLen + (answer ? 12 + rdLen : 0);
        byte[] dns = new byte[dnsLen];
        dns[0] = p[o];
        dns[1] = p[o + 1];
        dns[2] = (byte) ((p[o + 2] & 0x79) | 0x80);      // QR=1, зберігаємо opcode і RD
        dns[3] = (byte) 0x80;                              // RA=1, RCODE=0
        dns[5] = 1;                                        // QDCOUNT
        dns[7] = (byte) (answer ? 1 : 0);                  // ANCOUNT
        System.arraycopy(p, o + 12, dns, 12, qLen);
        if (answer) {
            int a = 12 + qLen;
            dns[a] = (byte) 0xC0;                          // вказівник на ім'я в питанні
            dns[a + 1] = 0x0C;
            put16(dns, a + 2, q.qtype);
            put16(dns, a + 4, 1);                          // IN
            put16(dns, a + 6, 0);
            put16(dns, a + 8, BLOCKED_TTL);
            put16(dns, a + 10, rdLen);                     // далі нулі = 0.0.0.0 / ::
        }
        return wrap(q, dns, dnsLen);
    }

    /** Загортає DNS-відповідь в IPv4/UDP-пакет назад до застосунку, що питав. */
    static byte[] wrap(Query q, byte[] dns, int dnsLen) {
        int total = 28 + dnsLen;
        byte[] r = new byte[total];
        r[0] = 0x45;
        put16(r, 2, total);
        int id;
        synchronized (Dns.class) {
            ipId = (ipId + 1) & 0xFFFF;
            id = ipId;
        }
        put16(r, 4, id);
        r[6] = 0x40;                                       // Don't Fragment
        r[8] = 64;                                         // TTL
        r[9] = 17;                                         // UDP
        System.arraycopy(q.dstIp, 0, r, 12, 4);
        System.arraycopy(q.srcIp, 0, r, 16, 4);
        put16(r, 10, checksum(r, 0, 20, 0));

        put16(r, 20, q.dstPort);
        put16(r, 22, q.srcPort);
        put16(r, 24, 8 + dnsLen);
        System.arraycopy(dns, 0, r, 28, dnsLen);

        // Контрольна сума UDP з псевдозаголовком
        long pseudo = 0;
        pseudo += u16(r, 12) + u16(r, 14) + u16(r, 16) + u16(r, 18);
        pseudo += 17 + 8 + dnsLen;
        int cs = checksum(r, 20, 8 + dnsLen, pseudo);
        if (cs == 0) cs = 0xFFFF;
        put16(r, 26, cs);
        return r;
    }

    static int checksum(byte[] b, int off, int len, long initial) {
        long sum = initial;
        int i = off;
        int end = off + len;
        while (i + 1 < end) {
            sum += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end) sum += (b[i] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    static void put16(byte[] b, int off, int v) {
        b[off] = (byte) (v >> 8);
        b[off + 1] = (byte) v;
    }
}
