# xhttp — Xray core + XHTTP روی پورت 443

پروژه جدا از گیت‌وی پایتونی: هسته **Xray-core** با ترانسپورت **XHTTP** (شکسته‌شدن روی HTTP،
مقاوم در برابر DPI) روی پورت 443 از طریق دامنه Railway.

یک فرانت کوچک پایتونی جلوی Xray می‌نشیند و `/sub` را سرو می‌کند (مثل پروژه اصلی، بدون لاگین).

## لینک

`GET /` یا `GET /sub` یک لینک برمی‌گرداند:

```
vless://<uuid>@<domain>:443?security=tls&sni=<domain>&type=xhttp&mode=auto&path=/xh&host=<domain>#ALIREZArely
```

در کلاینت‌ها: Type = **xhttp** (یا Splithttp در کلاینت‌های قدیمی‌تر)، Mode = **auto**، Path = `/xh`.

## متغیرهای محیطی

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `UUID` | ساخته می‌شود | **حتماً ست کنید** |
| `PORT` | `8080` | پورت فرانت — Railway خودش ست می‌کند |
| `DOMAIN` | — | دامنه عمومی برای ساخت لینک |
| `TAG` | `ALIREZArely` | اسم کانفیگ |
| `XHTTP_PATH` | `/xh` | مسیر XHTTP |
| `XHTTP_MODE` | `auto` | حالت XHTTP (auto / packet / stream) |
| `DATA_DIR` | `/data` | مسیر ذخیره UUID |
| `XRAY_BIN` | `xray` | مسیر باینری Xray (فقط برای تست محلی) |

روی Railway مثل پروژه اصلی روی `PORT` + `8080` + `443` همزمان listen می‌شود.

## دیپلوی روی Railway

1. یک سرویس جدید بسازید و Repo را وصل کنید.
2. در تنظیمات سرویس، **Root Directory** را `xhttp` بگذارید.
3. متغیر `UUID` را ست کنید (یا Volume به `/data`).
4. لینک: `https://<domain>/sub`

Build خودش Xray-core را از Release گیت‌هاب دانلود می‌کند (نسخه داخل `Dockerfile` پین شده).

## تست محلی

```bash
cd xhttp
XRAY_BIN="path/to/xray" UUID=11111111-2222-3333-4444-555555555555 PORT=18090 python server.py
curl http://127.0.0.1:18090/sub
```

بعد کلاینت Xray با `network: xhttp` به همان پورت وصل می‌شود و تست می‌شود.
