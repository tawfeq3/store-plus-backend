admin.js


"use strict";

/*
 * Store Plus Admin Panel
 */

const API = "/api";

const TOKEN_KEY = "storeplus_admin_token";

let currentUsers = [];
let currentApps = [];


/* =========================
   Helpers
========================= */

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
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


async function apiRequest(
  url,
  options = {}
) {
  const token = getToken();

  const headers = {
    ...(options.headers || {}),
  };

  if (token) {
    headers.Authorization =
      `Bearer ${token}`;
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

  if (!response.ok) {
    throw new Error(
      data?.message ||
      data?.error ||
      `HTTP ${response.status}`
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

  const error =
    document.getElementById(
      "loginError"
    );

  error.textContent = "";

  if (!username || !password) {
    error.textContent =
      "أدخل اسم المستخدم وكلمة المرور.";

    return;
  }

  try {
    const data =
      await apiRequest(
        `${API}/login`,
        {
          method: "POST",

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

    if (!data?.token) {
      throw new Error(
        "لم يتم استلام رمز الدخول."
      );
    }

    if (
      data?.user?.role !==
      "admin"
    ) {
      throw new Error(
        "هذا الحساب ليس حساب مدير."
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

  } catch (err) {
    error.textContent =
      err.message ||
      "فشل تسجيل الدخول.";
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
   Page State
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
      await apiRequest(
        `${API}/admin/stats`
      );

    document.getElementById(
      "usersCount"
    ).textContent =
      data.users ?? 0;

    document.getElementById(
      "appsCount"
    ).textContent =
      data.apps ?? 0;

    document.getElementById(
      "downloadsCount"
    ).textContent =
      data.downloads ?? 0;

    document.getElementById(
      "jobsCount"
    ).textContent =
      data.installJobs ?? 0;

  } catch (err) {
    console.error(
      "Stats error:",
      err
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

  list.textContent =
    "جاري التحميل...";

  try {
    const data =
      await apiRequest(
        `${API}/admin/apps`
      );

    currentApps =
      Array.isArray(data)
        ? data
        : [];

    if (
      currentApps.length === 0
    ) {
      list.innerHTML =
        "<p>لا توجد تطبيقات.</p>";

      return;
    }

    list.innerHTML =
      currentApps
        .map(
          (app) => {
            const id =
              escapeHTML(
                String(
                  app.id ?? ""
                )
              );

            const name =
              escapeHTML(
                String(
                  app.name ?? ""
                )
              );

            const version =
              escapeHTML(
                String(
                  app.version ?? ""
                )
              );

            const category =
              escapeHTML(
                String(
                  app.category ?? ""
                )
              );

            const bundleId =
              escapeHTML(
                String(
                  app.bundleId ??
                  ""
                )
              );

            const ipa =
              app.hasIPA
                ? "متوفر"
                : "غير متوفر";

            return `
              <div class="app-item">

                <div>
                  <strong>
                    ${name}
                  </strong>

                  <div>
                    الإصدار:
                    ${version}
                  </div>

                  <div>
                    التصنيف:
                    ${category}
                  </div>

                  <div>
                    Bundle ID:
                    ${bundleId}
                  </div>

                  <div>
                    IPA:
                    ${ipa}
                  </div>
                </div>

                <button
                  type="button"
                  onclick="deleteApp('${id}')"
                >
                  حذف
                </button>

              </div>
            `;
          }
        )
        .join("");

  } catch (err) {
    console.error(
      "Apps error:",
      err
    );

    list.innerHTML =
      `<p class="error">
        ${escapeHTML(
          err.message ||
          "فشل تحميل التطبيقات."
        )}
      </p>`;
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

  const submitButton =
    form.querySelector(
      'button[type="submit"]'
    );

  message.textContent =
    "جاري رفع التطبيق...";

  submitButton.disabled =
    true;

  try {
    const formData =
      new FormData(form);

    await apiRequest(
      `${API}/admin/apps`,
      {
        method: "POST",
        body: formData,
      }
    );

    message.textContent =
      "تمت إضافة التطبيق بنجاح.";

    form.reset();

    await loadApps();
    await loadStats();

  } catch (err) {
    console.error(
      "Add app error:",
      err
    );

    message.textContent =
      err.message ||
      "فشل إضافة التطبيق.";

  } finally {
    submitButton.disabled =
      false;
  }
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
    await apiRequest(
      `${API}/admin/apps/${encodeURIComponent(
        id
      )}`,
      {
        method: "DELETE",
      }
    );

    await loadApps();
    await loadStats();

  } catch (err) {
    alert(
      err.message ||
      "فشل حذف التطبيق."
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

  list.textContent =
    "جاري التحميل...";

  try {
    const data =
      await apiRequest(
        `${API}/admin/users`
      );

    currentUsers =
      Array.isArray(data)
        ? data
        : [];

    updateCertificateUsers();

    if (
      currentUsers.length === 0
    ) {
      list.innerHTML =
        "<p>لا يوجد مستخدمون.</p>";

      return;
    }

    list.innerHTML =
      currentUsers
        .map(
          (user) => {
            const id =
              escapeHTML(
                String(
                  user.id ?? ""
                )
              );

            const username =
              escapeHTML(
                String(
                  user.username ??
                  ""
                )
              );

            const name =
              escapeHTML(
                String(
                  user.name ??
                  ""
                )
              );

            const role =
              escapeHTML(
                String(
                  user.role ??
                  ""
                )
              );

            const certificate =
              user.hasCertificate
                ? "مرتبطة ✓"
                : "لا توجد";

            return `
              <div class="user-item">

                <div>
                  <strong>
                    ${name}
                  </strong>

                  <div>
                    اسم المستخدم:
                    ${username}
                  </div>

                  <div>
                    الصلاحية:
                    ${role}
                  </div>

                  <div>
                    الشهادة:
                    ${certificate}
                  </div>
                </div>

              </div>
            `;
          }
        )
        .join("");

  } catch (err) {
    console.error(
      "Users error:",
      err
    );

    list.innerHTML =
      `<p class="error">
        ${escapeHTML(
          err.message ||
          "فشل تحميل المستخدمين."
        )}
      </p>`;
  }
}


/* =========================
   Certificate User Select
========================= */

function updateCertificateUsers() {
  const select =
    document.getElementById(
      "certificateUser"
    );

  if (!select) {
    return;
  }

  select.innerHTML =
    `
      <option value="">
        اختر المستخدم
      </option>
    `;

  currentUsers
    .filter(
      (user) =>
        user.role !==
        "admin"
    )
    .forEach(
      (user) => {
        const option =
          document.createElement(
            "option"
          );

        option.value =
          user.id;

        option.textContent =
          `${user.name || user.username} — ${user.username}`;

        select.appendChild(
          option
        );
      }
    );
}


/* =========================
   Upload Certificate
========================= */

async function uploadCertificate(
  event
) {
  event.preventDefault();

  const form =
    document.getElementById(
      "certificateForm"
    );

  const message =
    document.getElementById(
      "certificateMessage"
    );

  const submitButton =
    form.querySelector(
      'button[type="submit"]'
    );

  const p12 =
    document.getElementById(
      "certificateP12"
    ).files[0];

  const provision =
    document.getElementById(
      "certificateProvision"
    ).files[0];

  const p12Password =
    document.getElementById(
      "certificateP12Password"
    ).value;

  if (!p12) {
    message.textContent =
      "اختر ملف P12.";

    return;
  }

  if (!provision) {
    message.textContent =
      "اختر ملف MobileProvision.";

    return;
  }

  if (!p12Password) {
    message.textContent =
      "أدخل كلمة مرور P12.";

    return;
  }

  /*
   * FormData ترسل:
   *
   * userID
   * label
   * p12
   * p12Password
   * mobileprovision
   */

  const formData =
    new FormData(form);

  /*
   * نتأكد صراحةً من اسم الحقل.
   */

  formData.set(
    "p12Password",
    p12Password
  );

  message.textContent =
    "جاري رفع الشهادة...";

  submitButton.disabled =
    true;

  try {
    await apiRequest(
      `${API}/admin/certificates/upload`,
      {
        method: "POST",
        body: formData,
      }
    );

    message.textContent =
      "تم حفظ الشهادة للمستخدم بنجاح.";

    form.reset();

    /*
     * نعيد القيمة الافتراضية
     * لاسم الشهادة.
     */

    document.getElementById(
      "certificateLabel"
    ).value =
      "Certificate";

    await loadUsers();

  } catch (err) {
    console.error(
      "Certificate upload error:",
      err
    );

    message.textContent =
      err.message ||
      "فشل رفع الشهادة.";

  } finally {
    submitButton.disabled =
      false;
  }
}


/* =========================
   Escape HTML
========================= */

function escapeHTML(
  value
) {
  return String(value)
    .replace(
      /&/g,
      "&amp;"
    )
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    )
    .replace(
      /'/g,
      "&#039;"
    );
}


/* =========================
   Enter Login
========================= */

document.addEventListener(
  "keydown",
  (event) => {
    if (
      event.key ===
      "Enter"
    ) {
      const loginPage =
        document.getElementById(
          "loginPage"
        );

      if (
        loginPage &&
        !loginPage.classList.contains(
          "hidden"
        )
      ) {
        login();
      }
    }
  }
);


/* =========================
   Form Events
========================= */

document.addEventListener(
  "DOMContentLoaded",
  async () => {

    const appForm =
      document.getElementById(
        "addAppForm"
      );

    if (appForm) {
      appForm.addEventListener(
        "submit",
        addApp
      );
    }


    const certificateForm =
      document.getElementById(
        "certificateForm"
      );

    if (certificateForm) {
      certificateForm.addEventListener(
        "submit",
        uploadCertificate
      );
    }


    /*
     * إذا كان لدينا Token سابق
     * نفتح لوحة التحكم مباشرة.
     */

    if (getToken()) {

      showDashboard();

      try {
        await Promise.all([
          loadStats(),
          loadApps(),
          loadUsers(),
        ]);

      } catch (err) {
        console.error(
          "Initial loading error:",
          err
        );
      }

    } else {
      showLogin();
    }
  }
);


