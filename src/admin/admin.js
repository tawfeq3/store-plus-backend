"use strict";

/* =========================
   Store Plus Admin Panel
   Compatible with Backend v10
========================= */

const API_BASE = "";

/* =========================
   Helpers
========================= */

function getToken() {
  return localStorage.getItem("store_plus_token") || "";
}

function setToken(token) {
  localStorage.setItem("store_plus_token", token);
}

function clearToken() {
  localStorage.removeItem("store_plus_token");
}

function getUser() {
  try {
    return JSON.parse(
      localStorage.getItem("store_plus_user") || "null"
    );
  } catch {
    return null;
  }
}

function setUser(user) {
  localStorage.setItem(
    "store_plus_user",
    JSON.stringify(user)
  );
}

function clearUser() {
  localStorage.removeItem("store_plus_user");
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function apiFetch(url, options = {}) {
  const headers = {
    ...(options.headers || {}),
  };

  const token = getToken();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(
    `${API_BASE}${url}`,
    {
      ...options,
      headers,
    }
  );

  let data = null;

  const contentType =
    response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    data = await response.json().catch(() => null);
  } else {
    data = await response.text().catch(() => "");
  }

  if (!response.ok) {
    if (response.status === 401) {
      clearToken();
      clearUser();

      showLogin();

      throw new Error(
        "انتهت جلسة الدخول، سجل الدخول مرة أخرى."
      );
    }

    const message =
      data?.message ||
      data?.error ||
      `HTTP ${response.status}`;

    throw new Error(message);
  }

  return data;
}

/* =========================
   Login / Logout
========================= */

async function login() {
  const usernameInput =
    document.getElementById("username");

  const passwordInput =
    document.getElementById("password");

  const errorBox =
    document.getElementById("loginError");

  const username =
    String(usernameInput?.value || "").trim();

  const password =
    String(passwordInput?.value || "");

  if (!username || !password) {
    if (errorBox) {
      errorBox.textContent =
        "أدخل اسم المستخدم وكلمة المرور.";
    }

    return;
  }

  if (errorBox) {
    errorBox.textContent =
      "جاري تسجيل الدخول...";
  }

  try {
    const data = await apiFetch(
      "/api/login",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify({
          username,
          password,
        }),
      }
    );

    if (!data?.token) {
      throw new Error(
        "الخادم لم يرجع رمز الدخول."
      );
    }

    setToken(data.token);

    if (data.user) {
      setUser(data.user);
    }

    if (errorBox) {
      errorBox.textContent = "";
    }

    await showDashboard();

  } catch (error) {
    console.error(
      "Login error:",
      error
    );

    if (errorBox) {
      errorBox.textContent =
        error?.message ||
        "فشل تسجيل الدخول.";
    }
  }
}

function logout() {
  clearToken();
  clearUser();

  showLogin();

  const password =
    document.getElementById("password");

  if (password) {
    password.value = "";
  }
}

function showLogin() {
  const loginPage =
    document.getElementById("loginPage");

  const dashboard =
    document.getElementById("dashboard");

  if (loginPage) {
    loginPage.classList.remove("hidden");
  }

  if (dashboard) {
    dashboard.classList.add("hidden");
  }
}

async function showDashboard() {
  const loginPage =
    document.getElementById("loginPage");

  const dashboard =
    document.getElementById("dashboard");

  if (loginPage) {
    loginPage.classList.add("hidden");
  }

  if (dashboard) {
    dashboard.classList.remove("hidden");
  }

  await Promise.all([
    loadStats(),
    loadApps(),
    loadUsers(),
  ]);
}

/* =========================
   Stats
========================= */

async function loadStats() {
  try {
    const data = await apiFetch(
      "/api/admin/stats"
    );

    const usersCount =
      document.getElementById(
        "usersCount"
      );

    const appsCount =
      document.getElementById(
        "appsCount"
      );

    const downloadsCount =
      document.getElementById(
        "downloadsCount"
      );

    const jobsCount =
      document.getElementById(
        "jobsCount"
      );

    if (usersCount) {
      usersCount.textContent =
        Number(data?.users || 0);
    }

    if (appsCount) {
      appsCount.textContent =
        Number(data?.apps || 0);
    }

    if (downloadsCount) {
      downloadsCount.textContent =
        Number(data?.downloads || 0);
    }

    if (jobsCount) {
      jobsCount.textContent =
        Number(data?.installJobs || 0);
    }

  } catch (error) {
    console.error(
      "Stats error:",
      error
    );
  }
}

/* =========================
   Apps
========================= */

async function loadApps() {
  const list =
    document.getElementById(
      "appsList"
    );

  if (!list) {
    return;
  }

  list.innerHTML =
    "<p>جاري تحميل التطبيقات...</p>";

  try {
    const apps = await apiFetch(
      "/api/admin/apps"
    );

    if (!Array.isArray(apps) || apps.length === 0) {
      list.innerHTML =
        "<p>لا توجد تطبيقات حالياً.</p>";

      return;
    }

    list.innerHTML =
      apps
        .map((app) => {
          const id =
            escapeHTML(app.id);

          const name =
            escapeHTML(app.name);

          const version =
            escapeHTML(app.version);

          const category =
            escapeHTML(app.category);

          const description =
            escapeHTML(
              app.description
            );

          const ipaName =
            escapeHTML(
              app.ipaName ||
              "IPA"
            );

          const active =
            app.active !== false;

          const featured =
            app.featured === true;

          const icon =
            app.iconURL
              ? `
                <img
                  src="${escapeHTML(
                    app.iconURL
                  )}"
                  alt=""
                  class="app-icon"
                  onerror="this.style.display='none'"
                >
              `
              : `
                <div class="app-icon-placeholder">
                  📱
                </div>
              `;

          return `
            <div class="app-item">

              <div class="app-info">

                ${icon}

                <div>
                  <h3>
                    ${name}
                  </h3>

                  <p>
                    الإصدار:
                    ${version}
                  </p>

                  <p>
                    التصنيف:
                    ${category}
                  </p>

                  <p>
                    ${description}
                  </p>

                  <p>
                    ${
                      app.hasIPA
                        ? `📦 ${ipaName}`
                        : "⚠️ لا يوجد IPA"
                    }
                  </p>

                  ${
                    featured
                      ? `
                        <span class="badge">
                          ⭐ مميز
                        </span>
                      `
                      : ""
                  }

                  ${
                    active
                      ? `
                        <span class="badge">
                          نشط
                        </span>
                      `
                      : `
                        <span class="badge">
                          غير نشط
                        </span>
                      `
                  }

                </div>

              </div>

              <div class="app-actions">

                ${
                  app.hasIPA
                    ? `
                      <a
                        href="/api/apps/${encodeURIComponent(
                          id
                        )}/ipa"
                        class="button"
                        target="_blank"
                        rel="noopener"
                      >
                        تحميل IPA
                      </a>
                    `
                    : ""
                }

                <button
                  type="button"
                  onclick="deleteApp('${id}')"
                >
                  حذف
                </button>

              </div>

            </div>
          `;
        })
        .join("");

  } catch (error) {
    console.error(
      "Load apps error:",
      error
    );

    list.innerHTML = `
      <p class="error">
        فشل تحميل التطبيقات:
        ${escapeHTML(
          error?.message ||
          "خطأ غير معروف"
        )}
      </p>
    `;
  }
}

/* =========================
   Add App
========================= */

async function addApp(event) {
  event.preventDefault();

  const form =
    document.getElementById(
      "addAppForm"
    );

  const message =
    document.getElementById(
      "appMessage"
    );

  const ipaInput =
    document.getElementById(
      "appIPA"
    );

  if (!form || !ipaInput) {
    return;
  }

  const ipa =
    ipaInput.files?.[0];

  if (!ipa) {
    if (message) {
      message.textContent =
        "اختر ملف IPA أولاً.";
    }

    return;
  }

  if (
    !ipa.name
      .toLowerCase()
      .endsWith(".ipa")
  ) {
    if (message) {
      message.textContent =
        "يجب اختيار ملف بصيغة IPA.";
    }

    return;
  }

  const formData =
    new FormData(form);

  formData.set(
    "ipa",
    ipa,
    ipa.name
  );

  const featured =
    document.getElementById(
      "appFeatured"
    );

  formData.set(
    "featured",
    featured?.checked
      ? "true"
      : "false"
  );

  const submitButton =
    form.querySelector(
      'button[type="submit"]'
    );

  if (submitButton) {
    submitButton.disabled = true;
    submitButton.textContent =
      "جاري رفع التطبيق...";
  }

  if (message) {
    message.textContent =
      "جاري رفع ملف IPA، قد يستغرق ذلك وقتاً حسب حجم الملف...";
  }

  try {
    const data = await apiFetch(
      "/api/admin/apps",
      {
        method: "POST",
        body: formData,
      }
    );

    console.log(
      "App created:",
      data
    );

    if (message) {
      message.textContent =
        "✅ تمت إضافة التطبيق بنجاح.";
    }

    form.reset();

    await Promise.all([
      loadApps(),
      loadStats(),
    ]);

  } catch (error) {
    console.error(
      "Add app error:",
      error
    );

    if (message) {
      message.textContent =
        `❌ فشل إضافة التطبيق: ${
          error?.message ||
          "خطأ غير معروف"
        }`;
    }

  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent =
        "إضافة التطبيق";
    }
  }
}

/* =========================
   Delete App
========================= */

async function deleteApp(id) {
  if (!id) {
    return;
  }

  const confirmed =
    window.confirm(
      "هل أنت متأكد من حذف هذا التطبيق؟\n\nسيتم حذف التطبيق وملف IPA المرتبط به."
    );

  if (!confirmed) {
    return;
  }

  try {
    await apiFetch(
      `/api/admin/apps/${encodeURIComponent(
        id
      )}`,
      {
        method: "DELETE",
      }
    );

    await Promise.all([
      loadApps(),
      loadStats(),
    ]);

    alert(
      "تم حذف التطبيق بنجاح."
    );

  } catch (error) {
    console.error(
      "Delete app error:",
      error
    );

    alert(
      `فشل حذف التطبيق: ${
        error?.message ||
        "خطأ غير معروف"
      }`
    );
  }
}

/* =========================
   Users
========================= */

async function loadUsers() {
  const list =
    document.getElementById(
      "usersList"
    );

  if (!list) {
    return;
  }

  list.innerHTML =
    "<p>جاري تحميل المستخدمين...</p>";

  try {
    const users = await apiFetch(
      "/api/admin/users"
    );

    if (
      !Array.isArray(users) ||
      users.length === 0
    ) {
      list.innerHTML =
        "<p>لا يوجد مستخدمون.</p>";

      return;
    }

    list.innerHTML =
      users
        .map((user) => {
          const id =
            escapeHTML(user.id);

          const username =
            escapeHTML(
              user.username
            );

          const name =
            escapeHTML(
              user.name ||
              ""
            );

          const role =
            escapeHTML(
              user.role
            );

          return `
            <div class="user-item">

              <div>
                <strong>
                  ${name || username}
                </strong>

                <p>
                  اسم المستخدم:
                  ${username}
                </p>

                <p>
                  الصلاحية:
                  ${role}
                </p>

                <p>
                  ${
                    user.active
                      ? "🟢 الحساب نشط"
                      : "🔴 الحساب غير نشط"
                  }
                </p>

                <p>
                  ${
                    user.hasCertificate
                      ? "🔐 لديه شهادة مرتبطة"
                      : "⚠️ لا توجد شهادة"
                  }
                </p>
              </div>

            </div>
          `;
        })
        .join("");

  } catch (error) {
    console.error(
      "Load users error:",
      error
    );

    list.innerHTML = `
      <p class="error">
        فشل تحميل المستخدمين:
        ${escapeHTML(
          error?.message ||
          "خطأ غير معروف"
        )}
      </p>
    `;
  }
}

/* =========================
   Enter Key Login
========================= */

function setupLoginEvents() {
  const username =
    document.getElementById(
      "username"
    );

  const password =
    document.getElementById(
      "password"
    );

  if (username) {
    username.addEventListener(
      "keydown",
      (event) => {
        if (event.key === "Enter") {
          login();
        }
      }
    );
  }

  if (password) {
    password.addEventListener(
      "keydown",
      (event) => {
        if (event.key === "Enter") {
          login();
        }
      }
    );
  }
}

/* =========================
   Form Event
========================= */

function setupForm() {
  const form =
    document.getElementById(
      "addAppForm"
    );

  if (!form) {
    return;
  }

  form.addEventListener(
    "submit",
    addApp
  );
}

/* =========================
   Initial Load
========================= */

async function initialize() {
  setupLoginEvents();
  setupForm();

  const token =
    getToken();

  if (!token) {
    showLogin();
    return;
  }

  try {
    /*
     * نتأكد أن التوكن صالح عن طريق
     * طلب بيانات الإحصائيات.
     */
    await loadStats();

    await showDashboard();

  } catch (error) {
    console.error(
      "Initialization error:",
      error
    );

    clearToken();
    clearUser();

    showLogin();
  }
}

/* =========================
   Global Functions
========================= */

window.login =
  login;

window.logout =
  logout;

window.loadApps =
  loadApps;

window.loadUsers =
  loadUsers;

window.deleteApp =
  deleteApp;

/* =========================
   Start
========================= */

document.addEventListener(
  "DOMContentLoaded",
  initialize
);
