# LLM Security Checker

یک اسکریپت جامع برای انجام چک‌لیست امنیتی کامل برای LLM endpoints.

## ویژگی‌ها

این اسکریپت 12 دسته از تست‌های امنیتی را انجام می‌دهد:

1. **SSL/TLS & Connectivity Security** - بررسی HTTPS، گواهی SSL، و HSTS
2. **Authentication & Authorization** - تست session_id و احراز هویت
3. **Input Validation & Injection Attacks** - SQL، Command، XSS، Path Traversal، LDAP، XXE
4. **Rate Limiting & DoS Protection** - بررسی محدودیت نرخ درخواست
5. **Information Disclosure** - بررسی خطاهای تفصیلی و headers حساس
6. **Prompt Injection & Jailbreak** - **60+ حمله prompt injection** شامل:
   - Direct Instruction Override
   - System Prompt Extraction
   - Developer/Admin Mode Claims
   - Role-Playing Jailbreaks
   - DAN (Do Anything Now) Variants
   - Hypothetical Scenarios
   - Token Smuggling
   - Context Confusion
   - Encoding Bypass
   - Recursive Injection
   - Authority Claims
   - Social Engineering
   - Format Injection
   - Persona-Based Jailbreaks
   - Multi-Language Attacks (شامل فارسی)
   - و بسیاری دیگر...
7. **Model Extraction & Membership Inference** - بررسی فاش شدن اطلاعات مدل
8. **Response Validation & Output Encoding** - اعتبارسنجی JSON و encoding
9. **Security Headers** - بررسی headers امنیتی (CSP، X-Frame-Options، etc)
10. **Session Management** - تست session fixation و cookie flags
11. **Sensitive Data Handling** - بررسی فاش شدن session_id و PII
12. **Error Handling & Logging** - تست handling خطاها و payload بزرگ

## نصب

```bash
pip install -r requirements.txt
```

## استفاده

### استفاده پایه‌ای

```bash
python3 llm_security_checker.py
```

### با لاگ‌های پایه‌ای (-v)

```bash
python3 llm_security_checker.py -v
```

نمایش لاگ‌های پایه‌ای با timestamp:
- شروع تست‌ها
- وضعیت درخواست‌ها
- پیام‌های تشخیصی

### با لاگ‌های تفصیلی (-vv)

```bash
python3 llm_security_checker.py -vv
```

نمایش تمام جزئیات شامل:
- درخواست‌های HTTP (method، URL، payload، headers)
- پاسخ‌های HTTP (status code، headers، body)
- تمام لاگ‌های پایه‌ای

**نکته:** Headers حساس (Authorization، Cookie، Set-Cookie) برای امنیت مخفی می‌شوند.

### استفاده از Proxy

```bash
python3 llm_security_checker.py --proxy http://localhost:8080
```

### ترکیب گزینه‌ها

```bash
# لاگ‌های تفصیلی + Proxy
python3 llm_security_checker.py -vv --proxy http://localhost:8080

# لاگ‌های پایه‌ای + Proxy
python3 llm_security_checker.py -v --proxy http://localhost:8080
```

## خروجی

اسکریپت نتایج را با رنگ‌های مختلف نمایش می‌دهد:

- ✓ **PASS** (سبز): تست موفق
- ✗ **FAIL** (قرمز): آسیب‌پذیری شناسایی شد
- ⚠ **WARN** (زرد): هشدار یا مسئله احتمالی
- ℹ **INFO** (آبی): اطلاعات تشخیصی

## نتیجه نهایی

اسکریپت یک امتیاز امنیتی (0-100%) محاسبه می‌کند:

- **80%+**: GOOD (خوب)
- **60-80%**: FAIR (متوسط)
- **<60%**: POOR (ضعیف)

## گزینه‌های Command Line

```
-v, --verbose         افزایش سطح verbosity (-v برای پایه‌ای، -vv برای تفصیلی)
--proxy PROXY         استفاده از HTTP/HTTPS proxy (مثال: http://localhost:8080)
--curl-file FILE      تجزیه فایل curl و استخراج URL، headers، cookies
--url URL             آدرس تارگت LLM (مثال: https://api.example.com/chat)
--headers JSON        Headers سفارشی به صورت JSON (مثال: '{"Authorization":"Bearer token"}')
--data JSON           Request body سفارشی به صورت JSON (مثال: '{"question":"test","user_id":"123"}')
--method METHOD       HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS) - پیش‌فرض: POST
--log-file FILE       ثبت تمام درخواست‌ها و پاسخ‌ها در فایل (مثال: scan.log)
--threads N           تعداد thread‌های موازی برای اسکن (1-20، پیش‌فرض: 1)
--output FILE         ذخیره نتایج اسکن در فایل (مثال: results.txt)
--resume              ادامه اسکن قطع شده از نقطه قطع
--checks LIST         بخش‌های خاص برای اسکن (مثال: ssl,auth,injection)
-h, --help            نمایش راهنما
```

### توضیح گزینه‌ها:

- **`--curl-file`**: فایل curl را تجزیه کرده و تمام مشخصات (URL، headers، cookies) را استخراج می‌کند
- **`--url`**: آدرس تارگت را مستقیم مشخص می‌کند (الزامی اگر `--curl-file` استفاده نشود)
- **`--headers`**: Headers اضافی یا جایگزین را به صورت JSON object مشخص می‌کند
  - می‌تواند با `--curl-file` استفاده شود (merge می‌شود)
  - می‌تواند با `--url` استفاده شود (جایگزین می‌شود)
- **`--data`**: Request body را به صورت JSON object مشخص می‌کند
  - می‌تواند با `--curl-file` استفاده شود (override می‌کند)
  - می‌تواند با `--url` استفاده شود (جایگزین می‌شود)
  - اختیاری است (برای GET requests نیازی نیست)
- **`--method`**: HTTP method را مشخص می‌کند
  - پیش‌فرض: POST
  - می‌تواند با `--curl-file` استفاده شود (override می‌کند)
  - می‌تواند با `--url` استفاده شود (جایگزین می‌شود)
- **`--log-file`**: تمام درخواست‌ها و پاسخ‌ها را در فایل ثبت می‌کند
  - شامل timestamps، headers، payloads، و responses
  - حساس داده‌ها (Authorization، Cookies) به صورت `***REDACTED***` ثبت می‌شوند
  - Thread-safe برای اسکن‌های موازی
- **`--threads`**: تعداد thread‌های موازی را کنترل می‌کند
  - 1-20 threads (پیش‌فرض: 1)
  - threads بیشتر = اسکن سریع‌تر
  - توصیه: 5-10 برای اسکن معمول
- **`--output`**: نتایج اسکن را در فایل ذخیره می‌کند
  - ANSI colors حذف می‌شوند (فقط متن ساده)
  - Thread-safe برای اسکن‌های موازی
  - نتایج هم روی console و هم در فایل ذخیره می‌شوند
- **`--resume`**: اسکن قطع شده را ادامه می‌دهد
  - state در `.scan_state.json` ذخیره می‌شود
  - فقط برای همان URL کار می‌کند
  - می‌توانید threads و دیگر گزینه‌ها را تغییر دهید
- **`--checks`**: بخش‌های خاص را برای اسکن انتخاب می‌کند
  - 13 بخش دستیاب: ssl, auth, input, rate, info, injection, extraction, response, headers, session, sensitive, llm, error
  - با کاما جدا کنید: `--checks ssl,auth,injection`
  - برای اسکن‌های سریع و فوکوس‌شده مفید است

## مثال‌های استفاده

### استفاده پایه‌ای

```bash
# اجرای ساده
python3 llm_security_checker.py

# دیدن لاگ‌های پایه‌ای
python3 llm_security_checker.py -v

# دیدن تمام جزئیات درخواست و پاسخ
python3 llm_security_checker.py -vv

# استفاده از Burp Suite proxy
python3 llm_security_checker.py --proxy http://localhost:8080

# ترکیب: لاگ تفصیلی + Burp proxy
python3 llm_security_checker.py -vv --proxy http://localhost:8080

# ترکیب: لاگ تفصیلی + Zaproxy
python3 llm_security_checker.py -vv --proxy http://localhost:8090
```

### استفاده با فایل Curl

```bash
# تجزیه فایل curl و اسکن با مشخصات آن
python3 llm_security_checker.py --curl-file request.curl

# تجزیه فایل curl + لاگ‌های پایه‌ای
python3 llm_security_checker.py --curl-file request.curl -v

# تجزیه فایل curl + لاگ‌های تفصیلی
python3 llm_security_checker.py --curl-file request.curl -vv

# تجزیه فایل curl + استفاده از proxy
python3 llm_security_checker.py --curl-file request.curl --proxy http://localhost:8080

# تجزیه فایل curl + لاگ تفصیلی + proxy
python3 llm_security_checker.py --curl-file request.curl -vv --proxy http://localhost:8080

# تجزیه فایل curl + اضافه کردن headers سفارشی
python3 llm_security_checker.py --curl-file request.curl --headers '{"Authorization":"Bearer token123"}'

# تجزیه فایل curl + جایگزینی headers
python3 llm_security_checker.py --curl-file request.curl --headers '{"X-API-Key":"key123","X-Custom":"value"}'
```

### استفاده با URL و Headers سفارشی

```bash
# فقط URL (با default headers)
python3 llm_security_checker.py --url https://api.example.com/chat

# URL + یک header سفارشی
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token"}'

# URL + چند header سفارشی
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token","X-API-Key":"key123"}'

# URL + headers + لاگ‌های تفصیلی
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token"}' -vv

# URL + headers + proxy
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token"}' --proxy http://localhost:8080

# URL + headers + لاگ تفصیلی + proxy
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token"}' -vv --proxy http://localhost:8080
```

### استفاده با Request Data سفارشی

```bash
# URL + custom data
python3 llm_security_checker.py --url https://api.example.com/chat --data '{"question":"test"}'

# URL + custom data با چند فیلد
python3 llm_security_checker.py --url https://api.example.com/chat --data '{"question":"test","user_id":"123","model":"gpt-4"}'

# URL + headers + custom data
python3 llm_security_checker.py --url https://api.example.com/chat \
  --headers '{"Authorization":"Bearer token"}' \
  --data '{"question":"test","user_id":"123"}'

# URL + custom data + لاگ تفصیلی
python3 llm_security_checker.py --url https://api.example.com/chat \
  --data '{"prompt":"hello","model":"gpt-4"}' \
  -vv
```

### استفاده با HTTP Method سفارشی

```bash
# URL + GET method
python3 llm_security_checker.py --url https://api.example.com/chat --method GET

# URL + PUT method
python3 llm_security_checker.py --url https://api.example.com/chat --method PUT --data '{"id":"123","content":"updated"}'

# URL + DELETE method
python3 llm_security_checker.py --url https://api.example.com/chat --method DELETE

# URL + PATCH method
python3 llm_security_checker.py --url https://api.example.com/chat --method PATCH --data '{"status":"active"}'

# URL + custom method + headers + data
python3 llm_security_checker.py --url https://api.example.com/chat \
  --method PUT \
  --headers '{"Authorization":"Bearer token"}' \
  --data '{"question":"test","updated":true}' \
  -vv
```

### استفاده با Logging

```bash
# ساده - تمام درخواست‌ها و پاسخ‌ها ثبت می‌شوند
python3 llm_security_checker.py --url https://api.example.com/chat --log-file scan.log

# با verbose logging
python3 llm_security_checker.py --url https://api.example.com/chat --log-file scan.log -vv

# Curl file + logging
python3 llm_security_checker.py --curl-file request.curl --log-file scan.log

# تمام جزئیات در لاگ
python3 llm_security_checker.py --url https://api.example.com/chat \
  --headers '{"Authorization":"Bearer token"}' \
  --data '{"question":"test"}' \
  --log-file detailed_scan.log \
  -vv
```

### استفاده با Threads (اسکن موازی)

```bash
# 5 threads - سرعت معمول
python3 llm_security_checker.py --url https://api.example.com/chat --threads 5

# 10 threads - سرعت بالا
python3 llm_security_checker.py --url https://api.example.com/chat --threads 10

# 10 threads + logging
python3 llm_security_checker.py --url https://api.example.com/chat --threads 10 --log-file scan.log

# Curl file + 8 threads + logging
python3 llm_security_checker.py --curl-file request.curl --threads 8 --log-file scan.log
```

### استفاده با Output (ذخیره نتایج)

```bash
# ساده - نتایج در فایل ذخیره می‌شوند
python3 llm_security_checker.py --url https://api.example.com/chat --output results.txt

# با logging
python3 llm_security_checker.py --url https://api.example.com/chat \
  --output results.txt \
  --log-file scan.log

# با threads و output
python3 llm_security_checker.py --url https://api.example.com/chat \
  --output results.txt \
  --threads 10 \
  -v
```

### استفاده با Resume (ادامه اسکن قطع شده)

```bash
# اسکن شروع کنید
python3 llm_security_checker.py --url https://api.example.com/chat \
  --output results.txt \
  --threads 5

# اگر قطع شد (Ctrl+C)، ادامه دهید:
python3 llm_security_checker.py --url https://api.example.com/chat \
  --resume \
  --output results.txt

# Resume با تغییر threads
python3 llm_security_checker.py --url https://api.example.com/chat \
  --resume \
  --output results.txt \
  --threads 10
```

### استفاده با Selective Checks (بخش‌های خاص)

```bash
# فقط Prompt Injection (سریع)
python3 llm_security_checker.py --url https://api.example.com/chat --checks injection

# چند بخش
python3 llm_security_checker.py --url https://api.example.com/chat --checks ssl,auth,injection

# بخش‌های اساسی
python3 llm_security_checker.py --url https://api.example.com/chat \
  --checks ssl,auth,headers,session

# بخش‌های LLM
python3 llm_security_checker.py --url https://api.example.com/chat \
  --checks injection,extraction,llm \
  --threads 10
```

### ترکیب تمام گزینه‌ها

```bash
# Curl file + custom headers + logging + threads + output + resume
python3 llm_security_checker.py --curl-file request.curl \
  --headers '{"X-API-Key":"key123"}' \
  --threads 8 \
  --log-file scan.log \
  --output results.txt \
  --resume \
  -vv

# URL + headers + data + method + proxy + logging + threads + output
python3 llm_security_checker.py --url https://api.example.com/chat \
  --headers '{"Authorization":"Bearer token","X-Custom":"value"}' \
  --data '{"question":"test","user_id":"123"}' \
  --method POST \
  --proxy http://localhost:8080 \
  --threads 10 \
  --log-file full_scan.log \
  --output results.txt \
  -vv
```

### ایجاد فایل Curl

برای ذخیره curl command در فایل:

```bash
# روش 1: کپی مستقیم از مرورگر
# در Chrome/Firefox: DevTools > Network > کلیک راست بر درخواست > Copy > Copy as cURL

# روش 2: ذخیره در فایل
cat > request.curl << 'EOF'
curl 'https://example.com/api/chat' \
  -H 'accept: */*' \
  -H 'content-type: application/json' \
  -b 'session_id=abc123' \
  --data-raw '{"session_id":"abc123","question":"test"}'
EOF

# سپس اسکن کنید:
python3 llm_security_checker.py --curl-file request.curl
```

## توجهات

- برخی تست‌ها نیاز به بررسی دستی دارند
- این اسکریپت برای تست‌های آموزشی و تشخیصی است
- برای استفاده در محیط production، تست‌های اضافی لازم است
- هنگام استفاده از proxy، مطمئن شوید proxy شما درخواست‌های HTTPS را پشتیبانی می‌کند

## نویسنده

LLM Security Assessment Tool
