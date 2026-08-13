import "dotenv/config";

import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pg from "pg";
import multer from "multer";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const { Pool } = pg;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : undefined,
});

const app = express();

/* =========================
   Certificate Password Encryption
========================= */

const certificatePasswordKey =
  process.env.CERTIFICATE_PASSWORD_KEY;

if (!certificatePasswordKey) {
  throw new Error(
    "CERTIFICATE_PASSWORD_KEY is required."
  );
}

const encryptionKey = crypto
  .createHash("sha256")
  .update(certificatePasswordKey)
  .digest();

function encryptCertificatePassword(
  password: string
): string {
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    encryptionKey,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(password, "utf8"),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return [
    iv.toString("base64"),
    authTag.toString("base64"),
    encrypted.toString("base64"),
  ].join(".");
}

function decryptCertificatePassword(
  value: string
): string {
  const parts = value.split(".");

  if (parts.length !== 3) {
    throw new Error(
      "Invalid encrypted certificate password."
    );
  }

  const [
    ivBase64,
    authTagBase64,
    encryptedBase64,
  ] = parts;

  const decipher =
    crypto.createDecipheriv(
      "aes-256-gcm",
      encryptionKey,
      Buffer.from(ivBase64, "base64")
    );

  decipher.setAuthTag(
    Buffer.from(authTagBase64, "base64")
  );

  const decrypted =
    Buffer.concat([
      decipher.update(
        Buffer.from(
          encryptedBase64,
          "base64"
        )
      ),
      decipher.final(),
    ]);

  return decrypted.toString("utf8");
}

/* =========================
   CORS
========================= */

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
    ],
  })
);

app.use(
  express.json({
    limit: "10mb",
  })
);

app.use(
  express.urlencoded({
    extended: true,
  })
);

/* =========================
   Admin Static Files
========================= */

const adminDir = path.resolve(
  process.cwd(),
  "src",
  "admin"
);

app.use(
  "/admin",
  express.static(adminDir, {
    index: "admin.html",
  })
);

app.get(
  "/admin",
  (_req, res) => {
    return res.sendFile(
      path.join(
        adminDir,
        "admin.html"
      )
    );
  }
);

app.get(
  "/admin/admin.html",
  (_req, res) => {
    return res.sendFile(
      path.join(
        adminDir,
        "admin.html"
      )
    );
  }
);

/* =========================
   Storage
========================= */

const root = path.resolve(
  process.env.STORAGE_ROOT ||
    "/tmp/store-plus"
);

for (const directory of [
  "certificates",
  "jobs",
  "apps",
]) {
  fs.mkdirSync(
    path.join(root, directory),
    {
      recursive: true,
    }
  );
}

/* =========================
   Request Type
========================= */

type Req = express.Request & {
  user?: any;
};

/* =========================
   Database Schema
========================= */

async function ensureSchema() {
  try {
    const schemaPath = path.resolve(
      process.cwd(),
      "schema.sql"
    );

    if (fs.existsSync(schemaPath)) {
      const schema =
        await fs.promises.readFile(
          schemaPath,
          "utf8"
        );

      if (schema.trim()) {
        await db.query(schema);
      }
    }

    await db.query(`
      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS ipa_ref TEXT;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS ipa_original_name TEXT;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS ipa_size BIGINT;
    `);

    await db.query(`
      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT true;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT false;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS bundle_id TEXT;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS source_url TEXT;
    `);

    await db.query(`
      ALTER TABLE certificates
      ADD COLUMN IF NOT EXISTS password_encrypted TEXT;
    `);

    await db.query(`
      UPDATE apps
      SET
        bundle_id =
          COALESCE(
            NULLIF(bundle_id, ''),
            'com.storeplus.legacy'
          ),
        source_url =
          COALESCE(
            NULLIF(source_url, ''),
            ''
          )
      WHERE
        bundle_id IS NULL
        OR source_url IS NULL;
    `);

    console.log(
      "Database schema initialized successfully."
    );
  } catch (error) {
    console.error(
      "Database schema initialization error:",
      error
    );

    throw error;
  }
}

/* =========================
   Initial Admin
========================= */

async function ensureAdmin() {
  try {
    const username =
      process.env.ADMIN_USERNAME?.trim();

    const password =
      process.env.ADMIN_PASSWORD;

    const name =
      process.env.ADMIN_NAME?.trim() ||
      "Administrator";

    if (!username || !password) {
      console.log(
        "ADMIN_USERNAME / ADMIN_PASSWORD not configured."
      );

      return;
    }

    if (password.length < 8) {
      console.error(
        "ADMIN_PASSWORD must be at least 8 characters."
      );

      return;
    }

    const existing =
      await db.query(
        `
        SELECT id
        FROM users
        WHERE username = $1
        LIMIT 1
        `,
        [username]
      );

    if (existing.rowCount) {
      console.log(
        `Admin user "${username}" already exists.`
      );

      return;
    }

    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    await db.query(
      `
      INSERT INTO users
      (
        username,
        password_hash,
        name,
        role,
        active
      )
      VALUES
      (
        $1,
        $2,
        $3,
        'admin',
        true
      )
      `,
      [
        username,
        passwordHash,
        name,
      ]
    );

    console.log(
      `Initial admin "${username}" created successfully.`
    );
  } catch (error) {
    console.error(
      "Admin initialization error:",
      error
    );
  }
}

/* =========================
   Authentication
========================= */

const auth = (
  req: Req,
  res: express.Response,
  next: express.NextFunction
) => {
  try {
    const authorization =
      req.header("authorization") || "";

    const token =
      authorization
        .replace(
          /^Bearer\s+/i,
          ""
        )
        .trim();

    if (!token) {
      return res.status(401).json({
        error: "unauthorized",
      });
    }

    req.user =
      jwt.verify(
        token,
        process.env.JWT_SECRET!
      );

    return next();
  } catch {
    return res.status(401).json({
      error: "unauthorized",
    });
  }
};

/* =========================
   Admin Middleware
========================= */

const admin = (
  req: Req,
  res: express.Response,
  next: express.NextFunction
) => {
  if (
    req.user?.role === "admin"
  ) {
    return next();
  }

  return res.status(403).json({
    error: "admin_required",
  });
};

/* =========================
   Health
========================= */

app.get(
  "/api/health",
  async (_req, res) => {
    try {
      await db.query(
        "SELECT 1"
      );

      return res.json({
        ok: true,
        version: "12.0.0",
      });
    } catch (error) {
      console.error(
        "Health check error:",
        error
      );

      return res.status(503).json({
        ok: false,
      });
    }
  }
);

/* =========================
   Login
========================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const username =
        String(
          req.body?.username ||
            ""
        ).trim();

      const password =
        String(
          req.body?.password ||
            ""
        );

      if (
        !username ||
        !password
      ) {
        return res.status(400).json({
          error:
            "username_and_password_required",
        });
      }

      const result =
        await db.query(
          `
          SELECT
            id,
            username,
            password_hash,
            name,
            role
          FROM users
          WHERE username = $1
            AND active = true
          LIMIT 1
          `,
          [username]
        );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            "invalid_credentials",
        });
      }

      const user =
        result.rows[0];

      const validPassword =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!validPassword) {
        return res.status(401).json({
          error:
            "invalid_credentials",
        });
      }

      const token =
        jwt.sign(
          {
            id: user.id,
            role: user.role,
          },
          process.env.JWT_SECRET!,
          {
            expiresIn: "30d",
          }
        );

      return res.json({
        token,

        user: {
          id: user.id,
          username:
            user.username,
          name: user.name,
          role: user.role,
        },
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      return res.status(500).json({
        error:
          "login_failed",
      });
    }
  }
);

/* =========================
   Public Apps
========================= */

app.get(
  "/api/apps",
  async (_req, res) => {
    try {
      const result =
        await db.query(`
          SELECT
            id,
            name,
            version,
            description,
            category,
            bundle_id AS "bundleId",
            source_url AS "sourceURL",
            icon_url AS "iconURL",
            featured,

            CASE
              WHEN ipa_ref IS NOT NULL
              THEN true
              ELSE false
            END AS "hasIPA",

            ipa_original_name
              AS "ipaName",

            ipa_size
              AS "ipaSize",

            updated

          FROM apps

          WHERE active = true

          ORDER BY
            featured DESC,
            updated_at DESC
        `);

      return res.json(
        result.rows
      );
    } catch (error) {
      console.error(
        "Apps error:",
        error
      );

      return res.status(500).json({
        error:
          "apps_failed",
      });
    }
  }
);

/* =========================
   Admin Apps List
========================= */

app.get(
  "/api/admin/apps",
  auth,
  admin,
  async (_req, res) => {
    try {
      const result =
        await db.query(`
          SELECT
            id,
            name,
            version,
            description,
            category,
            bundle_id AS "bundleId",
            source_url AS "sourceURL",
            icon_url AS "iconURL",
            featured,
            active,

            ipa_ref IS NOT NULL
              AS "hasIPA",

            ipa_original_name
              AS "ipaName",

            ipa_size
              AS "ipaSize",

            updated

          FROM apps

          ORDER BY
            updated_at DESC
        `);

      return res.json(
        result.rows
      );
    } catch (error) {
      console.error(
        "Admin apps error:",
        error
      );

      return res.status(500).json({
        error:
          "admin_apps_failed",
      });
    }
  }
);

/* =========================
   IPA Upload
========================= */

const ipaUpload =
  multer({
    storage:
      multer.diskStorage({
        destination:
          (_req, _file, cb) => {
            cb(
              null,
              path.join(
                root,
                "apps"
              )
            );
          },

        filename:
          (_req, file, cb) => {
            const extension =
              path.extname(
                file.originalname ||
                  ""
              ).toLowerCase();

            const id =
              crypto.randomUUID();

            cb(
              null,
              `${id}${
                extension ||
                ".ipa"
              }`
            );
          },
      }),

    limits: {
      fileSize:
        1024 *
        1024 *
        1024,
    },

    fileFilter:
      (_req, file, cb) => {
        const extension =
          path.extname(
            file.originalname ||
              ""
          ).toLowerCase();

        if (
          extension !== ".ipa"
        ) {
          return cb(
            new Error(
              "Only .ipa files are allowed."
            )
          );
        }

        return cb(
          null,
          true
        );
      },
  });

/* =========================
   Add App
========================= */

app.post(
  "/api/admin/apps",
  auth,
  admin,

  ipaUpload.fields([
    {
      name: "ipa",
      maxCount: 1,
    },
    {
      name: "ipaFile",
      maxCount: 1,
    },
    {
      name: "file",
      maxCount: 1,
    },
  ]),

  async (
    req: Req,
    res
  ) => {
    let ipa:
      | Express.Multer.File
      | undefined;

    try {
      const files =
        req.files as
          | {
              ipa?:
                Express.Multer.File[];

              ipaFile?:
                Express.Multer.File[];

              file?:
                Express.Multer.File[];
            }
          | undefined;

      ipa =
        files?.ipa?.[0] ||
        files?.ipaFile?.[0] ||
        files?.file?.[0];

      const name =
        String(
          req.body?.name ||
            ""
        ).trim();

      const version =
        String(
          req.body?.version ||
            ""
        ).trim();

      const category =
        String(
          req.body?.category ||
            ""
        ).trim();

      const description =
        String(
          req.body?.description ||
            ""
        ).trim();

      const bundleId =
        String(
          req.body?.bundle_id ||
            req.body?.bundleId ||
            ""
        ).trim();

      const iconURL =
        String(
          req.body?.iconURL ||
            req.body?.iconUrl ||
            ""
        ).trim();

      const featured =
        req.body?.featured ===
          true ||
        req.body?.featured ===
          "true" ||
        req.body?.featured ===
          "1";

      if (
        !name ||
        !version ||
        !category ||
        !description ||
        !bundleId ||
        !ipa
      ) {
        if (ipa?.path) {
          await fs.promises
            .unlink(
              ipa.path
            )
            .catch(
              () => {}
            );
        }

        return res.status(400).json({
          error:
            "required_fields_missing",

          required: {
            name:
              !name,

            version:
              !version,

            category:
              !category,

            description:
              !description,

            bundle_id:
              !bundleId,

            ipa:
              !ipa,
          },
        });
      }

      if (
        !/^[A-Za-z0-9.-]+$/.test(
          bundleId
        )
      ) {
        if (ipa?.path) {
          await fs.promises
            .unlink(
              ipa.path
            )
            .catch(
              () => {}
            );
        }

        return res.status(400).json({
          error:
            "invalid_bundle_id",

          message:
            "Bundle ID غير صالح.",
        });
      }

      const ipaRef =
        path.basename(
          ipa.path
        );

      const sourceURL =
        `${req.protocol}://${req.get(
          "host"
        )}/api/files/apps/${encodeURIComponent(
          ipaRef
        )}`;

      const result =
        await db.query(
          `
          INSERT INTO apps
          (
            name,
            version,
            description,
            category,
            bundle_id,
            source_url,
            icon_url,
            featured,
            active,
            ipa_ref,
            ipa_original_name,
            ipa_size
          )

          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            true,
            $9,
            $10,
            $11
          )

          RETURNING
            id,
            name,
            version,
            description,
            category,
            bundle_id AS "bundleId",
            source_url AS "sourceURL",
            icon_url AS "iconURL",
            featured,
            active,
            ipa_original_name
              AS "ipaName",
            ipa_size
              AS "ipaSize",
            true AS "hasIPA"
          `,
          [
            name,
            version,
            description,
            category,
            bundleId,
            sourceURL,
            iconURL || null,
            featured,
            ipaRef,
            ipa.originalname,
            ipa.size,
          ]
        );

      return res.status(201).json({
        ok: true,
        app:
          result.rows[0],
      });
    } catch (error) {
      console.error(
        "Add app error:",
        error
      );

      if (ipa?.path) {
        await fs.promises
          .unlink(
            ipa.path
          )
          .catch(
            () => {}
          );
      }

      return res.status(500).json({
        error:
          "app_creation_failed",

        message:
          error instanceof Error
            ? error.message
            : "Unknown error",
      });
    }
  }
);

/* =========================
   Direct IPA File
========================= */

app.get(
  "/api/files/apps/:filename",
  async (
    req,
    res
  ) => {
    try {
      const filename =
        path.basename(
          req.params.filename
        );

      if (
        !filename ||
        filename !==
          req.params.filename
      ) {
        return res.status(400).json({
          error:
            "invalid_filename",
        });
      }

      const filePath =
        path.join(
          root,
          "apps",
          filename
        );

      try {
        await fs.promises.access(
          filePath,
          fs.constants.R_OK
        );
      } catch {
        return res.status(404).json({
          error:
            "ipa_file_not_found",
        });
      }

      return res.sendFile(
        filePath
      );
    } catch (error) {
      console.error(
        "Direct IPA error:",
        error
      );

      return res.status(500).json({
        error:
          "ipa_file_failed",
      });
    }
  }
);

/* =========================
   Download IPA
========================= */

app.get(
  "/api/apps/:id/ipa",
  async (
    req,
    res
  ) => {
    try {
      const result =
        await db.query(
          `
          SELECT
            id,
            name,
            ipa_ref,
            ipa_original_name

          FROM apps

          WHERE id = $1
            AND active = true
            AND ipa_ref IS NOT NULL

          LIMIT 1
          `,
          [
            req.params.id,
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error:
            "ipa_not_found",
        });
      }

      const appData =
        result.rows[0];

      const ipaPath =
        path.join(
          root,
          "apps",
          path.basename(
            appData.ipa_ref
          )
        );

      try {
        await fs.promises.access(
          ipaPath,
          fs.constants.R_OK
        );
      } catch {
        return res.status(404).json({
          error:
            "ipa_file_not_found",
        });
      }

      const filename =
        appData.ipa_original_name ||
        `${appData.name}.ipa`;

      res.setHeader(
        "Content-Type",
        "application/octet-stream"
      );

      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${encodeURIComponent(
          filename
        )}"`
      );

      return res.sendFile(
        ipaPath
      );
    } catch (error) {
      console.error(
        "IPA download error:",
        error
      );

      return res.status(500).json({
        error:
          "ipa_download_failed",
      });
    }
  }
);

/* =========================
   Delete App
========================= */

app.delete(
  "/api/admin/apps/:id",
  auth,
  admin,
  async (
    req: Req,
    res
  ) => {
    try {
      const result =
        await db.query(
          `
          SELECT
            ipa_ref

          FROM apps

          WHERE id = $1

          LIMIT 1
          `,
          [
            req.params.id,
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error:
            "app_not_found",
        });
      }

      const ipaRef =
        result.rows[0]
          .ipa_ref;

      await db.query(
        `
        DELETE FROM apps
        WHERE id = $1
        `,
        [
          req.params.id,
        ]
      );

      if (ipaRef) {
        const ipaPath =
          path.join(
            root,
            "apps",
            path.basename(
              ipaRef
            )
          );

        await fs.promises
          .unlink(
            ipaPath
          )
          .catch(
            () => {}
          );
      }

      return res.json({
        ok: true,
      });
    } catch (error) {
      console.error(
        "Delete app error:",
        error
      );

      return res.status(500).json({
        error:
          "app_delete_failed",
      });
    }
  }
);

/* =========================
   Install App
========================= */

app.post(
  "/api/install",
  auth,
  async (
    req: Req,
    res
  ) => {
    try {
      const appID =
        req.body?.appID ||
        req.body?.appId ||
        req.body?.id;

      if (!appID) {
        return res.status(400).json({
          error:
            "app_id_required",
        });
      }

      /*
       * شهادة المستخدم نفسه فقط.
       */
      const certificate =
        await db.query(
          `
          SELECT
            id,
            certificate_ref,
            profile_ref,
            password_encrypted
          FROM certificates

          WHERE user_id = $1
            AND status = 'active'

          ORDER BY created_at DESC

          LIMIT 1
          `,
          [
            req.user.id,
          ]
        );

      if (!certificate.rowCount) {
        return res.status(409).json({
          error:
            "certificate_not_linked",
        });
      }

      const certificateData =
        certificate.rows[0];

      /*
       * لا يمكن بدء عملية التوقيع
       * إذا كانت الشهادة القديمة
       * لا تحتوي كلمة مرور.
       */
      if (
        !certificateData
          .password_encrypted
      ) {
        return res.status(409).json({
          error:
            "certificate_password_missing",

          message:
            "الشهادة المرتبطة بهذا المستخدم لا تحتوي على كلمة مرور P12. يجب إعادة رفع الشهادة مع كلمة المرور.",
        });
      }

      /*
       * نفك التشفير داخل السيرفر فقط.
       *
       * كلمة المرور لا يتم إرسالها
       * إلى العميل.
       */
      let certificatePassword: string;

      try {
        certificatePassword =
          decryptCertificatePassword(
            certificateData
              .password_encrypted
          );
      } catch (error) {
        console.error(
          "Certificate password decrypt error:",
          error
        );

        return res.status(500).json({
          error:
            "certificate_password_decrypt_failed",
        });
      }

      if (
        !certificatePassword
      ) {
        return res.status(409).json({
          error:
            "certificate_password_empty",
        });
      }

      const appResult =
        await db.query(
          `
          SELECT
            id,
            name,
            version,
            bundle_id,
            ipa_ref
          FROM apps

          WHERE id = $1
            AND active = true

          LIMIT 1
          `,
          [
            appID,
          ]
        );

      if (!appResult.rowCount) {
        return res.status(404).json({
          error:
            "app_not_found",
        });
      }

      const appData =
        appResult.rows[0];

      if (
        !appData.ipa_ref
      ) {
        return res.status(409).json({
          error:
            "app_has_no_ipa",
        });
      }

      /*
       * ملاحظة:
       * certificatePassword لا يتم
       * إرجاعه للعميل.
       *
       * يتم استخدامه لاحقًا داخل
       * Signing Worker.
       */

      const job =
        await db.query(
          `
          INSERT INTO install_jobs
          (
            user_id,
            app_id,
            certificate_id,
            status,
            message
          )

          VALUES
          (
            $1,
            $2,
            $3,
            'queued',
            'في انتظار المعالجة'
          )

          RETURNING
            id,
            status,
            message,
            created_at
              AS "createdAt"
          `,
          [
            req.user.id,

            appData.id,

            certificateData.id,
          ]
        );

      /*
       * نستخدم المتغير هنا للتأكد
       * أن كلمة المرور تم فك تشفيرها
       * بنجاح، ولكن لا نسجلها
       * في الـlogs ولا نرسلها للعميل.
       */
      void certificatePassword;

      return res.status(202).json(
        job.rows[0]
      );
    } catch (error) {
      console.error(
        "Install error:",
        error
      );

      return res.status(500).json({
        error:
          "install_failed",
      });
    }
  }
);

/* =========================
   Install Status
========================= */

app.get(
  "/api/install/:id",
  auth,
  async (
    req: Req,
    res
  ) => {
    try {
      const result =
        await db.query(
          `
          SELECT
            j.id,
            j.status,
            j.message,
            j.install_url
              AS "installURL",
            a.name
              AS "appName",
            a.version,
            a.bundle_id
              AS "bundleId"

          FROM install_jobs j

          JOIN apps a
            ON a.id = j.app_id

          WHERE j.id = $1
            AND j.user_id = $2
          `,
          [
            req.params.id,
            req.user.id,
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error:
            "job_not_found",
        });
      }

      return res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Install status error:",
        error
      );

      return res.status(500).json({
        error:
          "install_status_failed",
      });
    }
  }
);

/* =========================
   Admin Stats
========================= */

app.get(
  "/api/admin/stats",
  auth,
  admin,
  async (
    _req,
    res
  ) => {
    try {
      const [
        users,
        apps,
        downloads,
        installJobs,
      ] =
        await Promise.all([
          db.query(
            "SELECT count(*)::int AS n FROM users"
          ),

          db.query(
            "SELECT count(*)::int AS n FROM apps"
          ),

          db.query(
            "SELECT count(*)::int AS n FROM downloads"
          ),

          db.query(
            "SELECT count(*)::int AS n FROM install_jobs"
          ),
        ]);

      return res.json({
        users:
          users.rows[0].n,

        apps:
          apps.rows[0].n,

        downloads:
          downloads.rows[0].n,

        installJobs:
          installJobs.rows[0].n,
      });
    } catch (error) {
      console.error(
        "Admin stats error:",
        error
      );

      return res.status(500).json({
        error:
          "stats_failed",
      });
    }
  }
);

/* =========================
   Certificate Upload
========================= */

const certificateUpload =
  multer({
    storage:
      multer.memoryStorage(),

    limits: {
      files: 2,

      fileSize:
        10 *
        1024 *
        1024,
    },
  });

app.post(
  "/api/admin/certificates/upload",
  auth,
  admin,

  certificateUpload.fields([
    {
      name: "p12",
      maxCount: 1,
    },
    {
      name: "mobileprovision",
      maxCount: 1,
    },
  ]),

  async (
    req: Req,
    res
  ) => {
    try {
      const files =
        req.files as {
          p12?:
            Express.Multer.File[];

          mobileprovision?:
            Express.Multer.File[];
        };

      const p12 =
        files?.p12?.[0];

      const mobileprovision =
        files?.mobileprovision?.[0];

      const userID =
        String(
          req.body?.userID ||
            ""
        ).trim();

      const certificatePassword =
        String(
          req.body?.password ||
            ""
        );

      const label =
        String(
          req.body?.label ||
            "Certificate"
        ).trim();

      if (
        !userID ||
        !p12 ||
        !mobileprovision ||
        !certificatePassword
      ) {
        return res.status(400).json({
          error:
            "missing_fields",

          required: {
            userID:
              !userID,

            p12:
              !p12,

            mobileprovision:
              !mobileprovision,

            password:
              !certificatePassword,
          },
        });
      }

      /*
       * تأكد أن المستخدم موجود.
       */
      const userResult =
        await db.query(
          `
          SELECT
            id
          FROM users

          WHERE id = $1

          LIMIT 1
          `,
          [
            userID,
          ]
        );

      if (!userResult.rowCount) {
        return res.status(404).json({
          error:
            "user_not_found",
        });
      }

      /*
       * نلغي الشهادة السابقة
       * لهذا المستخدم فقط.
       */
      await db.query(
        `
        UPDATE certificates

        SET status = 'revoked'

        WHERE user_id = $1
          AND status = 'active'
        `,
        [
          userID,
        ]
      );

      const certificateRef =
        crypto.randomUUID();

      const profileRef =
        crypto.randomUUID();

      /*
       * نخزن ملفات الشهادة
       * بأسماء عشوائية.
       */
      await fs.promises.writeFile(
        path.join(
          root,
          "certificates",
          `${certificateRef}.p12`
        ),
        p12.buffer
      );

      await fs.promises.writeFile(
        path.join(
          root,
          "certificates",
          `${profileRef}.mobileprovision`
        ),
        mobileprovision.buffer
      );

      /*
       * تشفير كلمة مرور P12
       * قبل تخزينها في قاعدة البيانات.
       */
      const encryptedPassword =
        encryptCertificatePassword(
          certificatePassword
        );

      const result =
        await db.query(
          `
          INSERT INTO certificates
          (
            user_id,
            label,
            certificate_ref,
            profile_ref,
            password_encrypted,
            status
          )

          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            'active'
          )

          RETURNING
            id,
            user_id,
            label,
            certificate_ref,
            profile_ref,
            status,
            created_at
          `,
          [
            userID,

            label,

            certificateRef,

            profileRef,

            encryptedPassword,
          ]
        );

      /*
       * لا نرجع كلمة المرور
       * ولا النسخة المشفرة للعميل.
       */
      return res.status(201).json({
        ok: true,

        certificate: {
          id:
            result.rows[0].id,

          userID:
            result.rows[0].user_id,

          label:
            result.rows[0].label,

          status:
            result.rows[0].status,

          createdAt:
            result.rows[0].created_at,
        },
      });
    } catch (error) {
      console.error(
        "Certificate upload error:",
        error
      );

      return res.status(500).json({
        error:
          "certificate_upload_failed",

        message:
          error instanceof Error
            ? error.message
            : "Unknown error",
      });
    }
  }
);

/* =========================
   Admin Users
========================= */

app.get(
  "/api/admin/users",
  auth,
  admin,
  async (
    _req,
    res
  ) => {
    try {
      const result =
        await db.query(`
          SELECT
            u.id,
            u.username,
            u.name,
            u.role,
            u.active,

            EXISTS (
              SELECT 1
              FROM certificates c

              WHERE c.user_id =
                u.id

                AND c.status =
                  'active'
            ) AS "hasCertificate"

          FROM users u

          ORDER BY
            created_at DESC
        `);

      return res.json(
        result.rows
      );
    } catch (error) {
      console.error(
        "Admin users error:",
        error
      );

      return res.status(500).json({
        error:
          "users_failed",
      });
    }
  }
);

/* =========================
   Admin Certificate Info
========================= */

app.get(
  "/api/admin/users/:id/certificate",
  auth,
  admin,
  async (
    req,
    res
  ) => {
    try {
      const result =
        await db.query(
          `
          SELECT
            c.id,
            c.user_id
              AS "userID",
            c.label,
            c.status,
            c.created_at
              AS "createdAt",

            CASE
              WHEN c.password_encrypted
                IS NOT NULL
              THEN true
              ELSE false
            END AS "hasPassword"

          FROM certificates c

          WHERE c.user_id = $1
            AND c.status = 'active'

          ORDER BY
            c.created_at DESC

          LIMIT 1
          `,
          [
            req.params.id,
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error:
            "certificate_not_found",
        });
      }

      return res.json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Certificate info error:",
        error
      );

      return res.status(500).json({
        error:
          "certificate_info_failed",
      });
    }
  }
);

/* =========================
   API 404
========================= */

app.use(
  "/api",
  (
    _req,
    res
  ) => {
    return res.status(404).json({
      error:
        "api_route_not_found",
    });
  }
);

/* =========================
   Errors
========================= */

app.use(
  (
    error: any,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ) => {
    console.error(
      "Server error:",
      error
    );

    if (
      error instanceof
      multer.MulterError
    ) {
      if (
        error.code ===
        "LIMIT_FILE_SIZE"
      ) {
        return res.status(413).json({
          error:
            "ipa_file_too_large",

          message:
            "حجم الملف أكبر من الحد المسموح به وهو 1GB.",
        });
      }

      return res.status(400).json({
        error:
          "file_upload_error",

        message:
          error.message,
      });
    }

    if (
      error?.message ===
      "Only .ipa files are allowed."
    ) {
      return res.status(400).json({
        error:
          "invalid_ipa_file",

        message:
          "يجب اختيار ملف بصيغة IPA.",
      });
    }

    return res.status(500).json({
      error:
        "internal_server_error",

      message:
        error?.message ||
        "Unknown error",
    });
  }
);

/* =========================
   Start Server
========================= */

const PORT =
  Number(
    process.env.PORT ||
      10000
  );

async function startServer() {
  await ensureSchema();

  await ensureAdmin();

  app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `Store Plus API v12 ready on port ${PORT}`
      );

      console.log(
        `Storage root: ${root}`
      );
    }
  );
}

startServer().catch(
  (error) => {
    console.error(
      "Server startup error:",
      error
    );

    process.exit(1);
  }
);


