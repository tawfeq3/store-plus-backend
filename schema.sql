CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- =========================================================
-- USERS
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  username TEXT UNIQUE NOT NULL,

  password_hash TEXT NOT NULL,

  name TEXT NOT NULL,

  role TEXT NOT NULL DEFAULT 'user',

  active BOOLEAN NOT NULL DEFAULT true,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- =========================================================
-- APPS
-- =========================================================

CREATE TABLE IF NOT EXISTS apps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  name TEXT NOT NULL,

  version TEXT NOT NULL,

  description TEXT,

  category TEXT,

  icon_url TEXT,

  bundle_id TEXT NOT NULL,

  source_url TEXT NOT NULL,

  featured BOOLEAN DEFAULT false,

  active BOOLEAN DEFAULT true,

  ipa_ref TEXT,

  ipa_original_name TEXT,

  ipa_size BIGINT,

  updated BOOLEAN DEFAULT true,

  created_at TIMESTAMPTZ DEFAULT now(),

  updated_at TIMESTAMPTZ DEFAULT now()
);


-- =========================================================
-- CERTIFICATES
-- =========================================================

CREATE TABLE IF NOT EXISTS certificates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  user_id UUID
    REFERENCES users(id)
    ON DELETE CASCADE
    NOT NULL,

  label TEXT NOT NULL,

  certificate_ref TEXT NOT NULL,

  profile_ref TEXT NOT NULL,

  /*
   * كلمة مرور ملف P12 الخاصة بهذه الشهادة.
   *
   * كل شهادة لها كلمة مرور مستقلة.
   */
  p12_password TEXT NOT NULL,

  status TEXT DEFAULT 'active',

  created_at TIMESTAMPTZ DEFAULT now()
);


-- =========================================================
-- CERTIFICATE INDEX
-- مستخدم واحد لا يملك إلا شهادة نشطة واحدة
-- =========================================================

CREATE UNIQUE INDEX IF NOT EXISTS one_active_cert
ON certificates(user_id)
WHERE status = 'active';


-- =========================================================
-- INSTALL JOBS
-- =========================================================

CREATE TABLE IF NOT EXISTS install_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  user_id UUID
    REFERENCES users(id)
    NOT NULL,

  app_id UUID
    REFERENCES apps(id)
    NOT NULL,

  certificate_id UUID
    REFERENCES certificates(id)
    NOT NULL,

  status TEXT DEFAULT 'queued',

  message TEXT,

  install_url TEXT,

  created_at TIMESTAMPTZ DEFAULT now(),

  updated_at TIMESTAMPTZ DEFAULT now()
);


-- =========================================================
-- DOWNLOADS
-- =========================================================

CREATE TABLE IF NOT EXISTS downloads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  user_id UUID
    REFERENCES users(id)
    NOT NULL,

  app_id UUID
    REFERENCES apps(id)
    NOT NULL,

  job_id UUID
    REFERENCES install_jobs(id)
    NOT NULL,

  created_at TIMESTAMPTZ DEFAULT now()
);


-- =========================================================
-- EXISTING DATABASE MIGRATION
-- =========================================================

/*
 * إذا كان جدول certificates موجودًا من قبل،
 * نضيف عمود كلمة مرور P12.
 */

ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS p12_password TEXT;


/*
 * إذا كانت هناك شهادات قديمة بدون كلمة مرور،
 * نضع قيمة مؤقتة حتى لا يفشل الـ schema.
 *
 * يجب تحديث هذه الشهادات من لوحة التحكم
 * بكلمة المرور الصحيحة قبل استخدامها للتوقيع.
 */

UPDATE certificates
SET p12_password = ''
WHERE p12_password IS NULL;


/*
 * بعد تحديث السجلات القديمة، نجعل الحقل
 * إلزاميًا للشهادات الجديدة.
 */

ALTER TABLE certificates
ALTER COLUMN p12_password SET NOT NULL;


/*
 * إضافة أعمدة IPA للتطبيقات القديمة
 * إذا لم تكن موجودة.
 */

ALTER TABLE apps
ADD COLUMN IF NOT EXISTS ipa_ref TEXT;

ALTER TABLE apps
ADD COLUMN IF NOT EXISTS ipa_original_name TEXT;

ALTER TABLE apps
ADD COLUMN IF NOT EXISTS ipa_size BIGINT;


/*
 * إضافة bundle/source للتطبيقات القديمة
 * إذا لم تكن موجودة.
 */

ALTER TABLE apps
ADD COLUMN IF NOT EXISTS bundle_id TEXT;

ALTER TABLE apps
ADD COLUMN IF NOT EXISTS source_url TEXT;

ALTER TABLE apps
ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT true;

ALTER TABLE apps
ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT false;


/*
 * حماية التطبيقات القديمة من NULL
 * إذا كانت قاعدة البيانات تحتوي عليها.
 */

UPDATE apps
SET bundle_id = 'com.storeplus.legacy'
WHERE bundle_id IS NULL
   OR bundle_id = '';

UPDATE apps
SET source_url = ''
WHERE source_url IS NULL;


/*
 * إذا كانت الأعمدة في قاعدة البيانات القديمة
 * تسمح بـ NULL، نجعلها إلزامية بعد معالجة
 * البيانات القديمة.
 */

ALTER TABLE apps
ALTER COLUMN bundle_id SET NOT NULL;

ALTER TABLE apps
ALTER COLUMN source_url SET NOT NULL;


-- =========================================================
-- INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS apps_active_index
ON apps(active);

CREATE INDEX IF NOT EXISTS apps_bundle_id_index
ON apps(bundle_id);

CREATE INDEX IF NOT EXISTS certificates_user_index
ON certificates(user_id);

CREATE INDEX IF NOT EXISTS certificates_status_index
ON certificates(status);

CREATE INDEX IF NOT EXISTS install_jobs_user_index
ON install_jobs(user_id);

CREATE INDEX IF NOT EXISTS install_jobs_app_index
ON install_jobs(app_id);

CREATE INDEX IF NOT EXISTS install_jobs_certificate_index
ON install_jobs(certificate_id);

CREATE INDEX IF NOT EXISTS downloads_user_index
ON downloads(user_id);

CREATE INDEX IF NOT EXISTS downloads_app_index
ON downloads(app_id);
