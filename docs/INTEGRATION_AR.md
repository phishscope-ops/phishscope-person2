# ازاي الجزء بتاعي (Person 2) بيتوصل بباقي الفريق

الخدمة دي مستقلة. كل حاجة HTTP + JSON. ما بتلمسش قاعدة بيانات الفريق ولا كود غيرها.

## الـ endpoints
| الاستخدام | الطلب | الرد |
|---|---|---|
| فحص رابط | POST /v1/urls/scan  {"url":"https://..."} | 202 {"scan_id","status":"queued","poll_url"} ثم GET /v1/scans/{id} |
| فحص إيميل | POST /v1/emails/scan  {"eml_base64":"..."} أو {"eml_text":"..."} | 202 زي الرابط. 413 لو كبير، 422 لو غلط |
| فحص SMS يدوي | POST /v1/sms/scan  {"body":"...","sender":"..."} | 202 + poll |
| حماية SMS تلقائية | POST /v1/protection/sms  {"body","sender","received_at","message_id"} | مباشر: {message_id,status,show_warning,verdict,action,reasons,links[]} |
| المتصفح الآمن | POST /v1/browser/precheck {"url"} | {verdict,action,browser:{open_allowed,interstitial,title,user_can_proceed}} |
| صحة | GET /health | {status,engine,threat_intel} |

شكل نتيجة الـ poll: {"scan_id","kind","status":"queued|running|completed|failed","result":{verdict,risk_score,action,confidence,reasons[],caveats[],evidence{}}}
القيم: verdict = safe/suspicious/malicious/unknown ، action = allow/warn/block/warn_unverified.
لو في X-API-Key مطلوب: ابعته في الهيدر. 401 لو غلط، 429 لو زودت طلبات.

## يتقال لمين إيه
- **تطبيق الموبايل (Flutter):** اعرض النتيجة حسب action مش حسب لون بس. لو unknown اعرض "مش متأكدين" مش "آمن". في الـ SMS التلقائي ابعت message_id وهيرجع ليك زي ما هو، ولو status مش ok اعتبر الرسالة غير مؤكدة. المتصفح الآمن: اعمل precheck قبل فتح أي رابط، وافتح فقط لو open_allowed=true أو المستخدم ضغط يكمل (user_can_proceed).
- **فريق ML:** محتاجين منكم خدمة HTTP: POST {base}/analyze/url أو /sms أو /email بجسم {"content":"...","context":{}} والرد {"label":"phishing|suspicious|legit","score":0..1,"reasons":[],"engine":"","version":""}. حطوا الـ base في P2_ENGINE_URL_BASE (والمفتاح في P2_ENGINE_API_KEY). لو وقعت أو رجعت حاجة غلط، الخدمة بترجع للقواعد المحلية وتعلّم النتيجة "degraded" ومش هتقول safe.
- **قاعدة البيانات:** مش محتاجة منكم حاجة. الخدمة بتخزن نتايج الفحص مؤقتاً في SQLite (7 أيام) ولو عايزين نتايج تتحفظ في الداتابيز بتاعتكم اطلبوا النتيجة من poll وخزنوها عندكم. ماتخزنوش نص الرسايل بدون موافقة المستخدم.
- **واجهة المستخدم (UI):** النصوص reasons و caveats جاهزة بالعربي. اعرضوا caveats تحت النتيجة. ما تعرضوش "آمن" لو verdict مش safe.
- **النشر:** Dockerfile جاهز، مجاني على Render. حطوا الـ env variables فوق.
