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

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================
   Admin Panel Static Files
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

app.get("/admin", (_req, res) => {
  return res.sendFile(
    path.join(adminDir, "admin.html")
  );
});

app.get("/admin/admin.html", (_req, res) => {
  return res.sendFile(
    path.join(adminDir, "admin.html")
  );
});

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

    /*
     * IPA fields.
     */
    await db.query(`
      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS ipa_ref TEXT;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS ipa_original_name TEXT;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS ipa_size BIGINT;
    `);

    /*
     * App fields.
     */
    await db.query(`
      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT true;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT false;

      ALTER TABLE apps
      ADD COLUMN IF NOT EXISTS bundle_id TEXT;
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
        .replace(/^Bearer\s+/i, "")
        .trim();

    if (!token) {
      return res.status(401).json({
        error: "unauthorized",
      });
    }

    req.user = jwt.verify(
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
   Admin
========================= */

const admin = (
  req: Req,
  res: express.Response,
  next: express.NextFunction
) => {
  if (req.user?.role === "admin") {
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
      await db.query("SELECT 1");

      return res.json({
        ok: true,
        version: "11.0.0",
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
          req.body?.username || ""
        ).trim();

      const password =
        String(
          req.body?.password || ""
        );

      if (!username || !password) {
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
        error: "login_failed",
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
            bundle_id AS "bundleID",
            icon_url AS "iconURL",
            featured,
            CASE
              WHEN ipa_ref IS NOT NULL
              THEN true
              ELSE false
            END AS "hasIPA",
            ipa_original_name AS "ipaName",
            ipa_size AS "ipaSize",
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
        error: "apps_failed",
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
            bundle_id AS "bundleID",
            icon_url AS "iconURL",
            featured,
            active,
            ipa_ref IS NOT NULL AS "hasIPA",
            ipa_original_name AS "ipaName",
            ipa_size AS "ipaSize",
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
   Admin Add App + IPA
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
              ipa?: Express.Multer.File[];
              ipaFile?: Express.Multer.File[];
              file?: Express.Multer.File[];
            }
          | undefined;

      ipa =
        files?.ipa?.[0] ||
        files?.ipaFile?.[0] ||
        files?.file?.[0];

      const name =
        String(
          req.body?.name || ""
        ).trim();

      const version =
        String(
          req.body?.version || ""
        ).trim();

      const category =
        String(
          req.body?.category ||
            ""
        ).trim();

      const bundleID =
        String(
          req.body?.bundleID ||
          req.body?.bundleId ||
          req.body?.bundle_id ||
          ""
        ).trim();

      const description =
        String(
          req.body?.description ||
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
        !bundleID ||
        !description ||
        !ipa
      ) {
        if (ipa?.path) {
          await fs.promises
            .unlink(ipa.path)
            .catch(() => {});
        }

        return res.status(400).json({
          error:
            "name_version_category_bundle_id_description_and_ipa_required",

          required: {
            name: !name,
            version: !version,
            category: !category,
            bundleID: !bundleID,
            description:
              !description,
            ipa: !ipa,
          },
        });
      }

      /*
       * Basic Bundle ID validation.
       *
       * Examples:
       * com.example.app
       * com.storeplus.gbox
       */
      const bundlePattern =
        /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

      if (
        !bundlePattern.test(
          bundleID
        )
      ) {
        if (ipa?.path) {
          await fs.promises
            .unlink(ipa.path)
            .catch(() => {});
        }

        return res.status(400).json({
          error:
            "invalid_bundle_id",

          message:
            "Bundle ID غير صالح. مثال: com.example.app",
        });
      }

      const ipaRef =
        path.basename(
          ipa.path
        );

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
              true,
              $8,
              $9,
              $10
            )
          RETURNING
            id,
            name,
            version,
            description,
            category,
            bundle_id AS "bundleID",
            icon_url AS "iconURL",
            featured,
            active,
            ipa_original_name AS "ipaName",
            ipa_size AS "ipaSize",
            true AS "hasIPA"
          `,
          [
            name,
            version,
            description,
            category,
            bundleID,
            iconURL ||
              null,
            featured,
            ipaRef,
            ipa.originalname,
            ipa.size,
          ]
        );

      return res.status(201).json({
        ok: true,
        app: result.rows[0],
      });
    } catch (error) {
      console.error(
        "Add app error:",
        error
      );

      if (ipa?.path) {
        await fs.promises
          .unlink(ipa.path)
          .catch(() => {});
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
          [req.params.id]
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
    req,
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
          [req.params.id]
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
        [req.params.id]
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
          .catch(() => {});
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

      const certificate =
        await db.query(
          `
          SELECT id
          FROM certificates
          WHERE user_id = $1
            AND status = 'active'
          LIMIT 1
          `,
          [req.user.id]
        );

      if (!certificate.rowCount) {
        return res.status(409).json({
          error:
            "certificate_not_linked",
        });
      }

      const appResult =
        await db.query(
          `
          SELECT
            id,
            ipa_ref
          FROM apps
          WHERE id = $1
            AND active = true
          LIMIT 1
          `,
          [appID]
        );

      if (!appResult.rowCount) {
        return res.status(404).json({
          error:
            "app_not_found",
        });
      }

      if (
        !appResult.rows[0]
          .ipa_ref
      ) {
        return res.status(409).json({
          error:
            "app_has_no_ipa",
        });
      }

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
            created_at AS "createdAt"
          `,
          [
            req.user.id,
            appID,
            certificate.rows[0]
              .id,
          ]
        );

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
            j.install_url AS "installURL",
            a.name AS "appName",
            a.version
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
        10 * 1024 * 1024,
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
          p12?: Express.Multer.File[];
          mobileprovision?: Express.Multer.File[];
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

      if (
        !userID ||
        !p12 ||
        !mobileprovision
      ) {
        return res.status(400).json({
          error:
            "missing_fields",
        });
      }

      await db.query(
        `
        UPDATE certificates
        SET status = 'revoked'
        WHERE user_id = $1
          AND status = 'active'
        `,
        [userID]
      );

      const certificateRef =
        crypto.randomUUID();

      const profileRef =
        crypto.randomUUID();

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

      const result =
        await db.query(
          `
          INSERT INTO certificates
            (
              user_id,
              label,
              certificate_ref,
              profile_ref
            )
          VALUES
            (
              $1,
              $2,
              $3,
              $4
            )
          RETURNING
            id,
            status
          `,
          [
            userID,

            String(
              req.body?.label ||
                "Certificate"
            ).trim(),

            certificateRef,
            profileRef,
          ]
        );

      return res.status(201).json(
        result.rows[0]
      );
    } catch (error) {
      console.error(
        "Certificate upload error:",
        error
      );

      return res.status(500).json({
        error:
          "certificate_upload_failed",
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
              WHERE c.user_id = u.id
                AND c.status = 'active'
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
   API 404
========================= */

app.use(
  "/api",
  (_req, res) => {
    return res.status(404).json({
      error:
        "api_route_not_found",
    });
  }
);

/* =========================
   Multer / General Errors
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
    process.env.PORT || 10000
  );

async function startServer() {
  await ensureSchema();

  await ensureAdmin();

  app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `Store Plus API v11 ready on port ${PORT}`
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


