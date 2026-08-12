"use strict";

/* =========================
   Configuration
========================= */

const API = "/api";

const TOKEN_KEY =
  "store_plus_admin_token";


/* =========================
   Helpers
========================= */

function getToken() {
  return localStorage.getItem(
    TOKEN_KEY
  );
}


function setToken(token) {
  localStorage.setItem(
    TOKEN_KEY,
    token
  );
}


function clearToken() {
  localStorage.removeItem(
    TOKEN_KEY
  );
}


function escapeHTML(value) {
  const div =
    document.createElement(
      "div"
    );

  div.textContent =
    value == null
      ? ""
      : String(value);

  return div.innerHTML;
}


function formatBytes(bytes) {
  const value =
    Number(bytes);

  if (
    !Number.isFinite(value) ||
    value <= 0
  ) {
    return "-";
  }

  const units = [
    "B",
    "KB",
    "MB",
    "GB",
  ];

  let size = value;
  let index = 0;

  while (
    size >= 1024 &&
    index <
      units.length - 1
  ) {
    size /= 1024;
    index++;
  }

  return `${size.toFixed(
    index === 0 ? 0 : 2
  )} ${units[index]}`;
}


function showLoginError(message) {
  const element =
    document.getElementById(
      "loginError"
    );

  if (element) {
    element.textContent =
      message || "";
  }
}


function showAppMessage(
  message,
  success = false
) {
  const element =
    document.getElementById(
      "appMessage"
    );

  if (!element) {
    return;
  }

  element.textContent =
    message || "";

  element.style.color =
    success
      ? "green"
      : "red";
}


/* =========================
   API Request
========================= */

async function apiFetch(
  url,
  options = {}
) {
  const token =
    getToken();

  const headers =
    new Headers(
      options.headers || {}
    );

  if (token) {
    headers.set(
      "Authorization",
      `Bearer ${token}`
    );
  }

  /*
   * لا نضع Content-Type يدويًا
   * عندما يكون body FormData.
   */
  if (
    options.body instanceof
    FormData
  ) {
    headers.delete(
      "Content-Type"
    );
  }

  const response =
    await fetch(
      url,
      {
        ...options,
        headers,
      }
    );

  let data = null;

  try {
    data =
      await response.json();
  } catch {
    data = null;
  }

  if (
    response.status === 401
  ) {
    clearToken();
    showLogin();

    throw new Error(
      "انتهت جلسة تسجيل الدخول."
    );
  }

  if (
    !response.ok
  ) {
    const message =
      data?.message ||
      data?.error ||
      `HTTP ${response.status}`;

    throw new Error(
      message
    );
  }

  return data;
}


/* =========================
   Login
========================= */

async function login() {
  const username =
    document
      .getElementById(
        "username"
      )
      .value
      .trim();

  const password =
    document
      .getElementById(
        "password"
      )
      .value;

  showLoginError("");

  if (
    !username ||
    !password
  ) {
    showLoginError(
      "أدخل اسم المستخدم وكلمة المرور."
    );

    return;
  }

  const button =
    document.querySelector(
      "#loginPage button"
    );

  if (button) {
    button.disabled =
      true;

    button.textContent =
      "جارٍ الدخول...";
  }

  try {
    const data =
      await apiFetch(
        `${API}/login`,
        {
          method:
            "POST",

          headers: {
            "Content-Type":
              "application/json",
          },

          body:
            JSON.stringify({
              username,
              password,
            }),
        }
      );

    if (
      !data?.token
    ) {
      throw new Error(
        "لم يتم استلام رمز الدخول."
      );
    }

    setToken(
      data.token
    );

    showDashboard();

    await Promise.all([
      loadStats(),
      loadApps(),
      loadUsers(),
    ]);
  } catch (error) {
    console.error(
      "Login error:",
      error
    );

    showLoginError(
      getFriendlyError(
        error
      )
    );
  } finally {
    if (button) {
      button.disabled =
        false;

      button.textContent =
        "دخول";
    }
  }
}


/* =========================
   Logout
========================= */

function logout() {
  clearToken();

  showLogin();

  const username =
    document.getElementById(
      "username"
    );

  const password =
    document.getElementById(
      "password"
    );

  if (username) {
    username.value = "";
  }

  if (password) {
    password.value = "";
  }
}


/* =========================
   Login / Dashboard UI
========================= */

function showLogin() {
  const loginPage =
    document.getElementById(
      "loginPage"
    );

  const dashboard =
    document.getElementById(
      "dashboard"
    );

  if (loginPage) {
    loginPage.classList.remove(
      "hidden"
    );
  }

  if (dashboard) {
    dashboard.classList.add(
      "hidden"
    );
  }
}


function showDashboard() {
  const loginPage =
    document.getElementById(
      "loginPage"
    );

  const dashboard =
    document.getElementById(
      "dashboard"
    );

  if (loginPage) {
    loginPage.classList.add(
      "hidden"
    );
  }

  if (dashboard) {
    dashboard.classList.remove(
      "hidden"
    );
  }
}


/* =========================
   Stats
========================= */

async function loadStats() {
  try {
    const data =
      await apiFetch(
        `${API}/admin/stats`
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
        data.users ?? 0;
    }

    if (appsCount) {
      appsCount.textContent =
        data.apps ?? 0;
    }

    if (downloadsCount) {
      downloadsCount.textContent =
        data.downloads ?? 0;
    }

    if (jobsCount) {
      jobsCount.textContent =
        data.installJobs ?? 0;
    }
  } catch (error) {
    console.error(
      "Stats error:",
      error
    );
  }
}


/* =========================
   Add App
========================= */

async function addApp(
  event
) {
  event.preventDefault();

  const form =
    document.getElementById(
      "addAppForm"
    );

  if (!form) {
    return;
  }

  const fileInput =
    document.getElementById(
      "appIPA"
    );

  const bundleInput =
    document.getElementById(
      "appBundleId"
    );

  const file =
    fileInput?.files?.[0];

  const bundleId =
    bundleInput?.value
      ?.trim() || "";

  if (!file) {
    showAppMessage(
      "اختر ملف IPA أولاً."
    );

    return;
  }

  if (!file.name
    .toLowerCase()
    .endsWith(".ipa")) {
    showAppMessage(
      "الملف يجب أن يكون بصيغة IPA."
    );

    return;
  }

  if (!bundleId) {
    showAppMessage(
      "أدخل Bundle ID للتطبيق."
    );

    return;
  }

  if (
    !/^[A-Za-z0-9.-]+$/.test(
      bundleId
    )
  ) {
    showAppMessage(
      "Bundle ID غير صالح. مثال: com.example.app"
    );

    return;
  }

  const formData =
    new FormData();

  formData.append(
    "name",
    document
      .getElementById(
        "appName"
      )
      .value
      .trim()
  );

  formData.append(
    "version",
    document
      .getElementById(
        "appVersion"
      )
      .value
      .trim()
  );

  formData.append(
    "category",
    document
      .getElementById(
        "appCategory"
      )
      .value
      .trim()
  );

  formData.append(
    "bundle_id",
    bundleId
  );

  formData.append(
    "iconURL",
    document
      .getElementById(
        "appIcon"
      )
      .value
      .trim()
  );

  formData.append(
    "description",
    document
      .getElementById(
        "appDescription"
      )
      .value
      .trim()
  );

  formData.append(
    "featured",
    document
      .getElementById(
        "appFeatured"
      )
      .checked
      ? "true"
      : "false"
  );

  formData.append(
    "ipa",
    file
  );

  const button =
    document.getElementById(
      "addAppButton"
    );

  if (button) {
    button.disabled =
      true;

    button.textContent =
      "جارٍ رفع التطبيق...";
  }

  showAppMessage(
    "جارٍ رفع ملف IPA وإضافة التطبيق..."
  );

  try {
    const data =
      await apiFetch(
        `${API}/admin/apps`,
        {
          method:
            "POST",

          body:
            formData,
        }
      );

    showAppMessage(
      "تمت إضافة التطبيق بنجاح.",
      true
    );

    form.reset();

    await Promise.all([
      loadApps(),
      loadStats(),
    ]);

    console.log(
      "Created app:",
      data.app
    );
  } catch (error) {
    console.error(
      "Add app error:",
      error
    );

    showAppMessage(
      getFriendlyError(
        error
      )
    );
  } finally {
    if (button) {
      button.disabled =
        false;

      button.textContent =
        "إضافة التطبيق";
    }
  }
}


/* =========================
   Load Apps
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
    "جاري التحميل...";

  try {
    const apps =
      await apiFetch(
        `${API}/admin/apps`
      );

    if (
      !Array.isArray(apps) ||
      apps.length === 0
    ) {
      list.innerHTML =
        "<p>لا توجد تطبيقات حالياً.</p>";

      return;
    }

    list.innerHTML =
      apps
        .map(
          (app) =>
            renderApp(
              app
            )
        )
        .join("");
  } catch (error) {
    console.error(
      "Apps error:",
      error
    );

    list.innerHTML =
      `<p class="error">${escapeHTML(
        getFriendlyError(
          error
        )
      )}</p>`;
  }
}


/* =========================
   Render App
========================= */

function renderApp(app) {
  const id =
    app.id;

  const name =
    escapeHTML(
      app.name
    );

  const version =
    escapeHTML(
      app.version
    );

  const category =
    escapeHTML(
      app.category
    );

  const description =
    escapeHTML(
      app.description
    );

  const bundleId =
    escapeHTML(
      app.bundleId ||
        app.bundle_id ||
        "-"
    );

  const ipaName =
    escapeHTML(
      app.ipaName ||
        "-"
    );

  const ipaSize =
    formatBytes(
      app.ipaSize
    );

  const sourceURL =
    app.sourceURL ||
    app.source_url ||
    "";

  return `
    <div class="app-item">

      <div class="app-info">

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
          Bundle ID:
          <strong>
            ${bundleId}
          </strong>
        </p>

        <p>
          IPA:
          ${ipaName}
          (${ipaSize})
        </p>

        <p>
          ${description}
        </p>

        ${
          sourceURL
            ? `
              <p>
                <a
                  href="${escapeHTML(
                    sourceURL
                  )}"
                  target="_blank"
                  rel="noopener"
                >
                  رابط IPA
                </a>
              </p>
            `
            : ""
        }

      </div>

      <div class="app-actions">

        <button
          type="button"
          onclick="deleteApp('${String(
            id
          ).replace(
            /'/g,
            "\\'"
          )}')"
        >
          حذف
        </button>

      </div>

    </div>
  `;
}


/* =========================
   Delete App
========================= */

async function deleteApp(
  id
) {
  if (
    !confirm(
      "هل أنت متأكد من حذف هذا التطبيق؟"
    )
  ) {
    return;
  }

  try {
    await apiFetch(
      `${API}/admin/apps/${encodeURIComponent(
        id
      )}`,
      {
        method:
          "DELETE",
      }
    );

    await Promise.all([
      loadApps(),
      loadStats(),
    ]);
  } catch (error) {
    console.error(
      "Delete app error:",
      error
    );

    alert(
      getFriendlyError(
        error
      )
    );
  }
}


/* =========================
   Load Users
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
    "جاري التحميل...";

  try {
    const users =
      await apiFetch(
        `${API}/admin/users`
      );

    if (
      !Array.isArray(users) ||
      users.length === 0
    ) {
      list.innerHTML =
        "<p>لا يوجد مستخدمون حالياً.</p>";

      return;
    }

    list.innerHTML = `
      <div class="users-table">

        <table>

          <thead>

            <tr>

              <th>
                ID
              </th>

              <th>
                اسم المستخدم
              </th>

              <th>
                الاسم
              </th>

              <th>
                الدور
              </th>

              <th>
                الحالة
              </th>

              <th>
                الشهادة
              </th>

            </tr>

          </thead>

          <tbody>

            ${users
              .map(
                (user) =>
                  `
                  <tr>

                    <td>
                      ${escapeHTML(
                        user.id
                      )}
                    </td>

                    <td>
                      ${escapeHTML(
                        user.username
                      )}
                    </td>

                    <td>
                      ${escapeHTML(
                        user.name
                      )}
                    </td>

                    <td>
                      ${escapeHTML(
                        user.role
                      )}
                    </td>

                    <td>
                      ${
                        user.active
                          ? "نشط"
                          : "غير نشط"
                      }
                    </td>

                    <td>
                      ${
                        user.hasCertificate
                          ? "مرتبطة"
                          : "غير مرتبطة"
                      }
                    </td>

                  </tr>
                  `
              )
              .join("")}

          </tbody>

        </table>

      </div>
    `;
  } catch (error) {
    console.error(
      "Users error:",
      error
    );

    list.innerHTML =
      `<p class="error">${escapeHTML(
        getFriendlyError(
          error
        )
      )}</p>`;
  }
}


/* =========================
   Friendly Errors
========================= */

function getFriendlyError(
  error
) {
  const message =
    error?.message ||
    String(error) ||
    "حدث خطأ غير معروف.";

  if (
    message.includes(
      "bundle_id"
    )
  ) {
    return (
      "Bundle ID مطلوب للتطبيق."
    );
  }

  if (
    message.includes(
      "source_url"
    )
  ) {
    return (
      "حدث خطأ في رابط ملف التطبيق. أعد المحاولة."
    );
  }

  if (
    message.includes(
      "invalid_bundle_id"
    )
  ) {
    return (
      "Bundle ID غير صالح."
    );
  }

  if (
    message.includes(
      "ipa_file_too_large"
    )
  ) {
    return (
      "حجم ملف IPA أكبر من 1GB."
    );
  }

  if (
    message.includes(
      "invalid_ipa_file"
    )
  ) {
    return (
      "يجب اختيار ملف IPA."
    );
  }

  if (
    message.includes(
      "invalid_credentials"
    )
  ) {
    return (
      "اسم المستخدم أو كلمة المرور غير صحيحة."
    );
  }

  if (
    message.includes(
      "certificate_not_linked"
    )
  ) {
    return (
      "لا توجد شهادة مرتبطة بهذا المستخدم."
    );
  }

  return message;
}


/* =========================
   Enter Key Login
========================= */

document.addEventListener(
  "DOMContentLoaded",
  () => {
    const form =
      document.getElementById(
        "addAppForm"
      );

    if (form) {
      form.addEventListener(
        "submit",
        addApp
      );
    }

    const password =
      document.getElementById(
        "password"
      );

    if (password) {
      password.addEventListener(
        "keydown",
        (event) => {
          if (
            event.key ===
            "Enter"
          ) {
            login();
          }
        }
      );
    }

    /*
     * إذا كان عندنا Token
     * ندخل مباشرة للوحة.
     */
    if (getToken()) {
      showDashboard();

      Promise.all([
        loadStats(),
        loadApps(),
        loadUsers(),
      ]).catch(
        (error) => {
          console.error(
            "Initial load error:",
            error
          );
        }
      );
    } else {
      showLogin();
    }
  }
);


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

window.loadStats =
  loadStats;

window.deleteApp =
  deleteApp;
