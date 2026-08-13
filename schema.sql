CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  name text NOT NULL,
  role text NOT NULL DEFAULT 'user',
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS apps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  version text NOT NULL,
  description text,
  category text,
  icon_url text,
  bundle_id text NOT NULL,
  source_url text NOT NULL,
  featured boolean DEFAULT false,
  active boolean DEFAULT true,
  updated boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS certificates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  user_id uuid
    REFERENCES users(id)
    ON DELETE CASCADE
    NOT NULL,

  label text NOT NULL,

  certificate_ref text NOT NULL,

  profile_ref text NOT NULL,

  /*
   * كلمة مرور P12 مشفرة.
   * لا يتم تخزين كلمة المرور كنص صريح.
   */
  password_encrypted text,

  status text DEFAULT 'active',

  created_at timestamptz DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_cert
ON certificates(user_id)
WHERE status = 'active';

CREATE TABLE IF NOT EXISTS install_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  user_id uuid
    REFERENCES users(id)
    NOT NULL,

  app_id uuid
    REFERENCES apps(id)
    NOT NULL,

  certificate_id uuid
    REFERENCES certificates(id)
    NOT NULL,

  status text DEFAULT 'queued',

  message text,

  install_url text,

  created_at timestamptz DEFAULT now(),

  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS downloads (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  user_id uuid
    REFERENCES users(id)
    NOT NULL,

  app_id uuid
    REFERENCES apps(id)
    NOT NULL,

  job_id uuid
    REFERENCES install_jobs(id)
    NOT NULL,

  created_at timestamptz DEFAULT now()
);

/*
 * إذا كانت قاعدة البيانات موجودة مسبقًا،
 * نضيف العمود بدون حذف البيانات القديمة.
 */
ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS password_encrypted text;
