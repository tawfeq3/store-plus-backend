"use strict";

/* =========================
   Store Plus Admin
========================= */

const API = "/api";

const TOKEN_KEY =
  "store_plus_admin_token";

const USER_KEY =
  "store_plus_admin_user";


/* =========================
   Helpers
========================= */

function getToken() {
  return localStorage.getItem(
    TOKEN_KEY
  );
}


function getUser() {
  try {
    const value =
      localStorage.getItem(
        USER_KEY
      );

    return value
      ? JSON.parse(value)
      : null;
  } catch {
    return null;
  }
}


function setAuth(
  token,
  user
) {
  localStorage.setItem(
    TOKEN_KEY,
    token
  );

  localStorage.setItem(
    USER_KEY,
    JSON.stringify(user)
  );
}


function clearAuth() {
  localStorage.removeItem(
    TOKEN_KEY
  );

  localStorage.removeItem(
    USER_KEY
  );
}


function escapeHTML(value) {
  return String(
    value ?? ""
  )
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


function showLogin() {
  const loginPage =
    document.getElementById(
      "loginPage"
    );

  const dashboard =
    document.getElementById(
      "dashboard"
    );

  loginPage?.classList.remove(
    "hidden"
  );

  dashboard?.classList.add(
    "hidden"
  );
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

  loginPage?.classList.add(
    "hidden"
  );

  dashboard?.classList.remove(
    "hidden"
  );
}


/* =========================
   API Request
========================= */

async function api(
  url,
  options = {}
) {
  const headers =
    new Headers(
      options.headers || {}
    );

  const token =
    getToken();

  if (token) {
    headers.set(
      "Authorization",
      `Bearer ${token}`
    );
  }

  /*
   * لا نضع Content-Type تلقائياً
   * إذا كان body هو FormData.
   */
  if (
    options.body &&
    !(options.body instanceof FormData) &&
    !headers.has(
      "Content-Type"
    )
  ) {
    headers.set(
      "Content-Type",
      "application/json"
    );
  }

  const response =
    await fetch(
      `${API}${url}`,
      {
        ...options,
        headers,
      }
    );

  let data = null;

  const contentType =
    response.headers.get(
      "content-type"
    ) || "";

  if (
    contentType.includes(
      "application/json"
    )
  ) {
    data =
      await response.json()
        .catch(() => null);
  } else {
    const text =
      await response.text()
        .catch(() => "");

    data = text
      ? { message: text }
      : null;
  }

  if (
    response.status === 401
  ) {
    clearAuth();
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
      translateError(
        message
      )
    );
  }

  return data;
}


/* =========================
   Error Translation
========================= */

function translateError(
  error
) {
  const messages = {
    unauthorized:
      "يجب تسجيل الدخول.",
    admin_required:
      "هذه الصفحة تتطلب صلاحيات المدير.",
    invalid_credentials:
      "اسم المستخدم أو كلمة المرور غير صحيحة.",
    username_and_password_required:
      "أدخل اسم المستخدم وكلمة المرور.",
    app_not_found:
      "التطبيق غير موجود.",
    app_has_no_ipa:
      "التطبيق لا يحتوي على ملف IPA.",
    ipa_not_found:
      "ملف IPA غير موجود.",
    ipa_file_not_found:
      "ملف IPA غير موجود على الخادم.",
    certificate_not_linked:
      "لا توجد شهادة مرتبطة بالمستخدم.",
    invalid_bundle_id:
      "Bundle ID غير صالح.",
    app_creation_failed:
      "فشل إنشاء التطبيق.",
    ipa_file_too_large:
      "حجم ملف IPA أكبر من 1GB.",
    invalid_ipa_file:
      "يجب اختيار ملف IPA صحيح.",
    file_upload_error:
      "حدث خطأ أثناء رفع الملف.",
    stats_failed:
      "فشل تحميل الإحصائيات.",
    users_failed:
      "فشل تحميل المستخدمين.",
    admin_apps_failed:
      "فشل تحميل التطبيقات.",
    app_delete_failed:
      "فشل حذف التطبيق.",
  };

  return (
    messages[error] ||
    error ||
    "حدث خطأ غير معروف."
  );
}


/* =========================
   Login
========================= */

async function login() {
  const usernameInput =
    document.getElementById(
      "username"
    );

  const passwordInput =
    document.getElementById(
      "password"
    );

  const errorElement =
    document.getElementById(
      "loginError"
    );

  const loginButton =
    document.getElementById(
      "loginButton"
    );

  const username =
    String(
      usernameInput?.value ||
        ""
    ).trim();

  const password =
    String(
      passwordInput?.value ||
        ""
    );

  if (
    !username ||
    !password
  ) {
    if (errorElement) {
      errorElement.textContent =
        "أدخل اسم المستخدم وكلمة المرور.";
    }

    return;
  }

  if (errorElement) {
    errorElement.textContent =
      "";
  }

  if (loginButton) {
    loginButton.disabled =
      true;

    loginButton.textContent =
      "جاري الدخول...";
  }

  try {
    const data =
      await api(
        "/login",
        {
          method: "POST",

          body: JSON.stringify({
            username,
            password,
          }),
        }
      );

    if (
      !data?.token
    ) {
      throw new Error(
        "لم يتم استلام رمز تسجيل الدخول."
      );
    }

    if (
      data.user?.role !==
      "admin"
    ) {
      throw new Error(
        "هذا الحساب ليس حساب مدير."
      );
    }

    setAuth(
      data.token,
      data.user
    );

    showDashboard();

    await loadDashboard();

  } catch (error) {
    console.error(
      "Login error:",
      error
    );

    if (errorElement) {
      errorElement.textContent =
        error.message ||
        "فشل تسجيل الدخول.";
    }

  } finally {
    if (loginButton) {
      loginButton.disabled =
        false;

      loginButton.textContent =
        "دخول";
    }
  }
}


/* =========================
   Logout
========================= */

function logout() {
  clearAuth();

  showLogin();

  const password =
    document.getElementById(
      "password"
    );

  if (password) {
    password.value =
      "";
  }
}


/* =========================
   Dashboard
========================= */

async function loadDashboard() {
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
    const data =
      await api(
        "/admin/stats"
      );

    const users =
      document.getElementById(
        "usersCount"
      );

    const apps =
      document.getElementById(
        "appsCount"
      );

    const downloads =
      document.getElementById(
        "downloadsCount"
      );

    const jobs =
      document.getElementById(
        "jobsCount"
      );

    if (users) {
      users.textContent =
        data?.users ?? 0;
    }

    if (apps) {
      apps.textContent =
        data?.apps ?? 0;
    }

    if (downloads) {
      downloads.textContent =
        data?.downloads ?? 0;
    }

    if (jobs) {
      jobs.textContent =
        data?.installJobs ?? 0;
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
  const container =
    document.getElementById(
      "appsList"
    );

  if (!container) {
    return;
  }

  container.innerHTML =
    "جاري تحميل التطبيقات...";

  try {
    const data =
      await api(
        "/admin/apps"
      );

    const apps =
      Array.isArray(data)
        ? data
        : Array.isArray(
            data?.apps
          )
        ? data.apps
        : [];

    if (!apps.length) {
      container.innerHTML =
        "<p>لا توجد تطبيقات حالياً.</p>";

      return;
    }

    container.innerHTML =
      apps
        .map(
          (app) =>
            `
            <div class="app-item">

              <div class="app-info">

                ${
                  app.iconURL
                    ? `
                      <img
                        src="${escapeHTML(
                          app.iconURL
                        )}"
                        alt=""
                        width="60"
                        height="60"
                      >
                    `
                    : ""
                }

                <div>

                  <h3>
                    ${escapeHTML(
                      app.name
                    )}
                  </h3>

                  <p>
                    الإصدار:
                    ${escapeHTML(
                      app.version
                    )}
                  </p>

                  <p>
                    Bundle ID:
                    <strong>
                      ${escapeHTML(
                        app.bundleID ||
                          app.bundleId ||
                          "-"
                      )}
                    </strong>
                  </p>

                  <p>
                    التصنيف:
                    ${escapeHTML(
                      app.category
                    )}
                  </p>

                  <p>
                    ${
                      app.hasIPA
                        ? "ملف IPA موجود"
                        : "لا يوجد ملف IPA"
                    }
                  </p>

                </div>

              </div>

              <div class="app-actions">

                ${
                  app.hasIPA
                    ? `
                      <a
                        href="/api/apps/${encodeURIComponent(
                          app.id
                        )}/ipa"
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
                  onclick="deleteApp('${escapeHTML(
                    app.id
                  )}')"
                >
                  حذف
                </button>

              </div>

            </div>
            `
        )
        .join("");

  } catch (error) {
    console.error(
      "Apps error:",
      error
    );

    container.innerHTML =
      `
      <div class="error">
        ${escapeHTML(
          error.message
        )}
      </div>
      `;
  }
}


/* =========================
   Delete App
========================= */

async function deleteApp(
  appID
) {
  if (!appID) {
    return;
  }

  const confirmed =
    window.confirm(
      "هل أنت متأكد من حذف هذا التطبيق وملف IPA المرتبط به؟"
    );

  if (!confirmed) {
    return;
  }

  try {
    await api(
      `/admin/apps/${encodeURIComponent(
        appID
      )}`,
      {
        method: "DELETE",
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

    window.alert(
      error.message ||
        "فشل حذف التطبيق."
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

  const message =
    document.getElementById(
      "appMessage"
    );

  const button =
    document.getElementById(
      "addAppButton"
    );

  if (!form) {
    return;
  }

  const name =
    document.getElementById(
      "appName"
    )?.value.trim();

  const version =
    document.getElementById(
      "appVersion"
    )?.value.trim();

  const category =
    document.getElementById(
      "appCategory"
    )?.value.trim();

  const bundleID =
    document.getElementById(
      "appBundleID"
    )?.value.trim();

  const iconURL =
    document.getElementById(
      "appIcon"
    )?.value.trim();

  const description =
    document.getElementById(
      "appDescription"
    )?.value.trim();

  const ipaInput =
    document.getElementById(
      "appIPA"
    );

  const featured =
    document.getElementById(
      "appFeatured"
    )?.checked || false;

  const ipaFile =
    ipaInput?.files?.[0];

  if (
    !name ||
    !version ||
    !category ||
    !bundleID ||
    !description ||
    !ipaFile
  ) {
    if (message) {
      message.innerHTML =
        `
        <div class="error">
          أكمل جميع الحقول المطلوبة واختر ملف IPA.
        </div>
        `;
    }

    return;
  }

  /*
   * Bundle ID format:
   * com.example.app
   */
  const bundlePattern =
    /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

  if (
    !bundlePattern.test(
      bundleID
    )
  ) {
    if (message) {
      message.innerHTML =
        `
        <div class="error">
          Bundle ID غير صالح.
          مثال:
          com.example.app
        </div>
        `;
    }

    return;
  }

  if (
    !ipaFile.name
      .toLowerCase()
      .endsWith(".ipa")
  ) {
    if (message) {
      message.innerHTML =
        `
        <div class="error">
          يجب اختيار ملف بصيغة IPA.
        </div>
        `;
    }

    return;
  }

  const formData =
    new FormData();

  formData.append(
    "name",
    name
  );

  formData.append(
    "version",
    version
  );

  formData.append(
    "category",
    category
  );

  /*
   * هذا هو الحقل الجديد
   * المطلوب من قاعدة البيانات.
   */
  formData.append(
    "bundleID",
    bundleID
  );

  formData.append(
    "description",
    description
  );

  formData.append(
    "iconURL",
    iconURL || ""
  );

  formData.append(
    "featured",
    featured
      ? "true"
      : "false"
  );

  formData.append(
    "ipa",
    ipaFile
  );

  if (message) {
    message.innerHTML =
      `
      <div>
        جاري رفع التطبيق...
      </div>
      `;
  }

  if (button) {
    button.disabled =
      true;

    button.textContent =
      "جاري الرفع...";
  }

  try {
    await api(
      "/admin/apps",
      {
        method: "POST",
        body: formData,
      }
    );

    if (message) {
      message.innerHTML =
        `
        <div>
          ✅ تمت إضافة التطبيق بنجاح.
        </div>
        `;
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
      message.innerHTML =
        `
        <div class="error">
          ❌ فشل إضافة التطبيق:
          ${escapeHTML(
            error.message
          )}
        </div>
        `;
    }

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
   Users
========================= */

async function loadUsers() {
  const container =
    document.getElementById(
      "usersList"
    );

  if (!container) {
    return;
  }

  container.innerHTML =
    "جاري تحميل المستخدمين...";

  try {
    const data =
      await api(
        "/admin/users"
      );

    const users =
      Array.isArray(data)
        ? data
        : Array.isArray(
            data?.users
          )
        ? data.users
        : [];

    if (!users.length) {
      container.innerHTML =
        "<p>لا يوجد مستخدمون حالياً.</p>";

      return;
    }

    container.innerHTML =
      `
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

    container.innerHTML =
      `
      <div class="error">
        ${escapeHTML(
          error.message
        )}
      </div>
      `;
  }
}


/* =========================
   Enter Key Login
========================= */

document.addEventListener(
  "DOMContentLoaded",
  () => {
    const loginInputs =
      document.querySelectorAll(
        "#username, #password"
      );

    loginInputs.forEach(
      (input) => {
        input.addEventListener(
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
    );


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


    /*
     * Restore session.
     */
    const token =
      getToken();

    const user =
      getUser();

    if (
      token &&
      user?.role === "admin"
    ) {
      showDashboard();

      loadDashboard()
        .catch(
          (error) => {
            console.error(
              "Dashboard error:",
              error
            );
          }
        );
    } else {
      clearAuth();
      showLogin();
    }
  }
);


/* =========================
   Make Functions Global
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


