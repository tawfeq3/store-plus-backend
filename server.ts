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

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
  })
);

app.use(express.json());

/*
 * Render Free لا يدعم Persistent Disk.
 * لذلك نستخدم /tmp بدل /var/data.
 *
 * ملاحظة:
 * الملفات الموجودة في /tmp قد تختفي عند إعادة تشغيل الخدمة.
 */
const root = path.resolve(
  process.env.STORAGE_ROOT || "/tmp/store-plus"
);

for (const d of ["certificates", "jobs"]) {
  fs.mkdirSync(path.join(root, d), {
    recursive: true,
  });
}

type Req = express.Request & {
  user?: any;
};

const auth = (
  req: Req,
  res: express.Response,
  next: express.NextFunction
) => {
  try {
    const t = (
      req.header("authorization") || ""
    ).replace(/^Bearer /, "");

    req.user = jwt.verify(
      t,
      process.env.JWT_SECRET!
    );

    next();
  } catch {
    res.status(401).json({
      error: "unauthorized",
    });
  }
};

const admin = (
  req: Req,
  res: express.Response,
  next: express.NextFunction
) =>
  req.user?.role === "admin"
    ? next()
    : res.status(403).json({
        error: "admin_required",
      });

/* Health */

app.get("/api/health", async (_q, r) => {
  try {
    await db.query("select 1");

    r.json({
      ok: true,
      version: "9.0.0",
    });
  } catch {
    r.status(503).json({
      ok: false,
    });
  }
});

/* Login */

app.post("/api/login", async (q, r) => {
  const {
    username,
    password,
  } = q.body || {};

  const x = await db.query(
    "select id,username,password_hash,name,role from users where username=$1 and active=true",
    [username]
  );

  if (
    !x.rowCount ||
    !(await bcrypt.compare(
      password || "",
      x.rows[0].password_hash
    ))
  ) {
    return r.status(401).json({
      error: "invalid_credentials",
    });
  }

  const u = x.rows[0];

  r.json({
    token: jwt.sign(
      {
        id: u.id,
        role: u.role,
      },
      process.env.JWT_SECRET!,
      {
        expiresIn: "30d",
      }
    ),
    user: {
      id: u.id,
      username: u.username,
      name: u.name,
      role: u.role,
    },
  });
});

/* Apps */

app.get("/api/apps", async (_q, r) => {
  r.json(
    (
      await db.query(
        'select id,name,version,description,category,icon_url as "iconURL",featured,updated from apps where active=true order by featured desc,updated_at desc'
      )
    ).rows
  );
});

/* Install */

app.post(
  "/api/install",
  auth,
  async (q: Req, r) => {
    const c = await db.query(
      "select id from certificates where user_id=$1 and status='active' limit 1",
      [q.user.id]
    );

    if (!c.rowCount) {
      return r.status(409).json({
        error: "certificate_not_linked",
      });
    }

    const a = await db.query(
      "select id from apps where id=$1 and active=true",
      [q.body?.appID]
    );

    if (!a.rowCount) {
      return r.status(404).json({
        error: "app_not_found",
      });
    }

    r.status(202).json(
  (
    await db.query(
      `
      insert into install_jobs
        (user_id, app_id, certificate_id, status, message)
      values
        ($1, $2, $3, 'queued', 'في انتظار المعالجة')
      returning
        id,
        status,
        message,
        created_at as "createdAt"
      `,
      [
        q.user.id,
        q.body?.appID,
        c.rows[0].id
      ]
    )
  ).rows[0]
);
  }
);

app.get(
  "/api/install/:id",
  auth,
  async (q: Req, r) => {
    const x = await db.query(
      `
      select
        j.id,
        j.status,
        j.message,
        j.install_url as "installURL",
        a.name as "appName",
        a.version
      from install_jobs j
      join apps a on a.id = j.app_id
      where j.id = $1
        and j.user_id = $2
      `,
      [
        q.params.id,
        q.user.id
      ]
    );

    if (x.rowCount) {
      r.json(x.rows[0]);
    } else {
      r.status(404).json({
        error: "job_not_found"
      });
    }
  }
);

/* Admin stats */

app.get(
  "/api/admin/stats",
  auth,
  admin,
  async (_q, r) => {
    const [u, a, d, j] = await Promise.all(
      ["users", "apps", "downloads", "install_jobs"].map(
        (t) =>
          db.query(
            `select count(*)::int n from ${t}`
          )
      )
    );

    r.json({
      users: u.rows[0].n,
      apps: a.rows[0].n,
      downloads: d.rows[0].n,
      installJobs: j.rows[0].n
    });
  }
);

/* Certificate upload */

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    files: 2,
    fileSize: 10 * 1024 * 1024
  }
});

app.post(
  "/api/admin/certificates/upload",
  auth,
  admin,
  upload.fields([
    { name: "p12", maxCount: 1 },
    { name: "mobileprovision", maxCount: 1 }
  ]),
  async (q: Req, r) => {
    const f = q.files as {
      p12?: Express.Multer.File[];
      mobileprovision?: Express.Multer.File[];
    };

    const p = f?.p12?.[0];
    const m = f?.mobileprovision?.[0];
    const uid = String(q.body.userID || "");

    if (!uid || !p || !m) {
      return r.status(400).json({
        error: "missing_fields"
      });
    }

    await db.query(
      `
      update certificates
      set status = 'revoked'
      where user_id = $1
        and status = 'active'
      `,
      [uid]
    );

    const ref = crypto.randomUUID();
    const prof = crypto.randomUUID();

    await fs.writeFile(
      path.join(
        root,
        "certificates",
        ref + ".p12"
      ),
      p.buffer,
      { mode: 0o600 }
    );

    await fs.writeFile(
      path.join(
        root,
        "certificates",
        prof + ".mobileprovision"
      ),
      m.buffer,
      { mode: 0o600 }
    );

    const result = await db.query(
      `
      insert into certificates
        (user_id, label, certificate_ref, profile_ref)
      values
        ($1, $2, $3, $4)
      returning id, status
      `,
      [
        uid,
        q.body.label || "Certificate",
        ref,
        prof
      ]
    );

    r.status(201).json(result.rows[0]);
  }
);

/* Admin users */

app.get(
  "/api/admin/users",
  auth,
  admin,
  async (_q, r) => {
    const result = await db.query(
      `
      select
        u.id,
        u.username,
        u.name,
        u.role,
        u.active,
        exists(
          select 1
          from certificates c
          where c.user_id = u.id
            and c.status = 'active'
        ) as "hasCertificate"
      from users u
      order by created_at desc
      `
    );

    r.json(result.rows);
  }
);

/* Start server */

app.listen(
  Number(process.env.PORT || 10000),
  "0.0.0.0",
  () => {
    console.log("Store Plus API v9 ready");
  }
);
