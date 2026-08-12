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

    r.status(
