# NetSpecter v2.1 — Smart Auto-Pwn Pipeline

## الهدف
من فتح الأداة → الباسورد في الإيد. من غير أي قرار يدوي من الـ operator غير اختيار الـ adapter.

## Pipeline (6 مراحل تلقائية)

### المرحلة 1: Discovery (30 ثانية)
- Monitor mode على كل الـ channels (2.4 + 5 GHz)
- تجميع: كل APs + clients + signal strength + encryption class
- Hidden APs تتجمع في قائمة منفصلة

### المرحلة 2: Hidden Recovery (60 ثانية — بالتوازي)
- لكل hidden AP: probe harvest → beacon flood → deauth-reveal → vendor guess
- Corroboration scoring → الـ hidden AP يدخل الجدول الرئيسي بـ ESSID معروف

### المرحلة 3: Target Scoring (فوري)
كل AP ياخد score حسب:
- **Signal** (الأقرب أسهل): -40dBm = 100 نقطة، -80dBm = 10
- **Encryption** (الأضعف أسهل): WEP = 100، WPA2 = 50، WPA3 = 20
- **Clients connected** (أكتر = أسهل للـ handshake): 5+ = 30، 0 = 5
- **WPS advertised** = +40 (Pixie Dust فوري)
- **PMKID eligible** = +30 (بدون client)
- **النتيجة**: قائمة مرتبة، أول AP هو أسهل فريسة

### المرحلة 4: Attack Selection (فوري)
لكل AP، الـ SmartWizard يختار:
1. WPS? → Pixie Dust أولاً (ثواني) → fallback online brute
2. PMKID eligible? → harvest بدون أي client (60 ثانية)
3. WEP? → IVs collection + crack (دقائق)
4. WPA2? → deauth targeted + handshake capture
5. WPA3 transition? → downgrade attack

### المرحلة 5: Mass Execution (متوازي)
- Scheduler يشغل 4 workers
- Channel arbitration: APs على نفس الـ channel بالدور
- كل job ليه timeout حugged من الـ phase

### المرحلة 6: Auto-Crack + Report
- كل capture يروح للـ crack queue فوراً
- Wordlist افتراضية: rockyou (لو موجودة) + default router passwords
- اللي اتحسر → يظهر في الـ GUI أخضر + يروح في الـ report
- اللي فشل → يظهر أحمر + السبب

## الـ GUI: زرار واحد
**"Auto-Pwn"** — يشغل الـ pipeline كله ويعرض live:
```
┌─────────────────────────────────────────────┐
│  🔍 Scanning... 23 APs found (17 sec)       │
│  👻 3 hidden networks → 2 recovered         │
│  🎯 6 targets ranked                        │
│                                             │
│  #1 Linksys-5G   WPA2  -45dBm  🔓 CRACKED   │
│     └ Password: sunshine1985                │
│  #2 TP-LINK_A3F2 WPA2+PS -52dBm  ⏳ WPS...  │
│  #3 NETGEAR      WEP   -60dBm  🔓 CRACKED   │
│     └ Key: AA:BB:CC:DD:EE                   │
│  #4 Office-5G    WPA2  -70dBm  ⏳ deauth... │
│  #5 Hidden-X1    ???   -75dBm  ❌ no clients│
│  #6 Vodafone-xx  WPA3  -78dBm  ⏭ skipped   │
└─────────────────────────────────────────────┘
```
