# NetSpecter — دليل التشغيل السريع (عربي)

> للاختبار المصرح به فقط — على شبكاتك أو بموافقة كتابية.

## التثبيت

```bash
sudo apt install -y build-essential pkg-config libgtk-4-dev libadwaita-1-dev
cargo build --workspace --release
```

النواتج في `target/release/`: `netspecter` (الواجهة) و `netspecter-cli` (التيرمينال) و `netspecter-agent` (الصلاحيات).

## التشغيل (CLI — الأسهل)

```bash
./target/release/netspecter-cli
```

1. اختار كارت الواي فاي (الألفا لو واصل، وسيب الكارت الداخلي متصل عشان النت).
2. اعمل scan واستنى دقايق عشان الشبكات البعيدة والمخفية تظهر.
3. اختار شبكة من اللستة → شوف تفاصيلها والهجوم المقترح.
4. نفذ الهجوم من القايمة بالترتيب ده (الأرخص الأول):
   - **NULL PIN** ثم **Default PINs** — لحظي لو اتقبل
   - **Pixie Dust** — ثواني لو الشيبست ضعيفة
   - **Online brute** — ساعات، آخر حل (ممكن يقفل الراوتر مؤقتا)

## الشبكات المخفية

الأداة بتكشفها تلقائيا: الأول سلبي (سماع probe-requests)، ولو ماطلعتش بتعمل
deauth مقصود لعميل متصل عشان يجبره يبعت الاسم (بيفصل لحظيا — استخدمه بموافقة).

## أوامر سريعة

```bash
netspecter-cli --help      # المساعدة
netspecter-cli --version   # رقم النسخة
```

## ملاحظات عملية

- لازم root (أو pkexec) عشان الـ monitor mode.
- كارت الألفا (Atheros AR9271 وأخواتها) أنسب حاجة للهجوم؛ الكارت الداخلي للاتصال بس.
- الـ Evil Twin محتاج `hostapd` و `dnsmasq` و `lighttpd` متسطبين.
- التقارير بتطلع HTML/PDF/JSON من صفحة Reports.
