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

/* =========================
   Database
========================= */

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : undefined,
});

/* =========================
   App
========================= */

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
  })
);

app.use(express.json());

/* =========================
   Storage
========================= */

const root = path.resolve(
  process.env.STORAGE_ROOT || "/tmp/store-plus"
);

for (const directory of ["certificates", "jobs"]) {
  fs.mkdirSync(path.join(root, directory), {
    recursive: true,
  });
}

/* =========================
   Types
========================= */

type Req = express.Request & {
  user?: any;
};

/* =========================
   Create Initial Admin
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

    const existing = await db.query(
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
      await bcrypt.hash(password, 12);

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
    const token = (
      req.header("authorization") || ""
    ).replace(/^Bearer /, "");

    if (!token) {
      return res.status(401).json({
        error: "unauthorized",
      });
    }

    req.user = jwt.verify(
      token,
      process.env.JWT_SECRET!
    );

    next();
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

app.get("/api/health", async (_req, res) => {
  try {
    await db.query("SELECT 1");

    return res.json({
      ok: true,
      version: "9.0.0",
    });
  } catch {
    return res.status(503).json({
      ok: false,
    });
  }
});

/* =========================
   Login
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const {
      username,
      password,
    } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        error: "username_and_password_required",
      });
    }

    const result = await db.query(
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
      `,
      [username]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(
        password || "",
        result.rows[0].password_hash
      ))
    ) {
      return res.status(401).json({
        error: "invalid_credentials",
      });
    }

    const user = result.rows[0];

    const token = jwt.sign(
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
        username: user.username,
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
});

/* =========================
   Apps
========================= */

app.get("/api/apps", async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT
        id,
        name,
        version,
        description,
        category,
        icon_url AS "iconURL",
        featured,
        updated
      FROM apps
      WHERE active = true
      ORDER BY featured DESC, updated_at DESC
    `);

    return res.json(result.rows);
  } catch (error) {
    console.error(
      "Apps error:",
      error
    );

    return res.status(500).json({
      error: "apps_failed",
    });
  }
});

/* =========================
   Install App
========================= */

app.post(
  "/api/install",
  auth,
  async (req: Req, res) => {
    try {
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
          error: "certificate_not_linked",
        });
      }

      const appResult =
        await db.query(
          `
          SELECT id
          FROM apps
          WHERE id = $1
            AND active = true
          `,
          [req.body?.appID]
        );

      if (!appResult.rowCount) {
        return res.status(404).json({
          error: "app_not_found",
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
            req.body.appID,
            certificate.rows[0].id,
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
        error: "install_failed",
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
  async (req: Req, res) => {
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
          error: "job_not_found",
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
        error: "install_status_failed",
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
  async (_req, res) => {
    try {
      const [
        users,
        apps,
        downloads,
        installJobs,
      ] = await Promise.all([
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
        users: users.rows[0].n,
        apps: apps.rows[0].n,
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
        error: "stats_failed",
      });
    }
  }
);

/* =========================
   Certificate Upload
========================= */

const upload = multer({
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
  upload.fields([
    {
      name: "p12",
      maxCount: 1,
    },
    {
      name: "mobileprovision",
      maxCount: 1,
    },
  ]),
  async (req: Req, res) => {
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
          req.body?.userID || ""
        );

      if (
        !userID ||
        !p12 ||
        !mobileprovision
      ) {
        return res.status(400).json({
          error: "missing_fields",
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
          certificateRef +
            ".p12"
        ),
        p12.buffer
      );

      await fs.promises.writeFile(
        path.join(
          root,
          "certificates",
          profileRef +
            ".mobileprovision"
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
            req.body?.label ||
              "Certificate",
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
  async (_req, res) => {
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
          ORDER BY created_at DESC
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
        error: "users_failed",
      });
    }
  }
);

/* =========================
   Start Server
========================= */

const PORT = Number(
  process.env.PORT || 10000
);

async function startServer() {
  /*
   * Create the initial Admin before
   * accepting requests.
   */
  await ensureAdmin();

  app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `Store Plus API v9 ready on port ${PORT}`
      );
    }
  );
}

startServer().catch((error) => {
  console.error(
    "Server startup error:",
    error
  );

  process.exit(1);
});
