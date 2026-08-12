# Store Plus Backend v9
جاهز كأساس للنشر على Render.

## Render
Build: `npm ci && npm run build`
Start: `npm start`
Health: `/api/health`

أنشئ PostgreSQL ثم نفّذ `db/schema.sql`.

`PUBLIC_BASE_URL` يجب أن يكون رابط خدمة HTTPS بعد أول Deploy.

**لا ترفع P12 أو MobileProvision أو كلمات المرور إلى GitHub.**

هذه الحزمة تنشر API وقاعدة البيانات والتخزين الأساسي. Worker الخاص بالتوقيع يحتاج بيئة منفصلة تحتوي أدوات التوقيع؛ سنوصله بعد نجاح API.
