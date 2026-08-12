let token =
  localStorage.getItem("store_plus_token");

const API = "";

function showDashboard() {
  document
    .getElementById("loginPage")
    .classList.add("hidden");

  document
    .getElementById("dashboard")
    .classList.remove("hidden");

  loadStats();
  loadApps();
  loadUsers();
}

function showLogin() {
  document
    .getElementById("loginPage")
    .classList.remove("hidden");

  document
    .getElementById("dashboard")
    .classList.add("hidden");
}

async function login() {
  const username =
    document
      .getElementById("username")
      .value
      .trim();

  const password =
    document
      .getElementById("password")
      .value;

  const error =
    document.getElementById(
      "loginError"
    );

  error.textContent = "";

  try {
    const response =
      await fetch(
        `${API}/api/login`,
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

    const data =
      await response.json();

    if (!response.ok) {
      throw new Error(
        data.error ||
          "فشل تسجيل الدخول"
      );
    }

    token = data.token;

    localStorage.setItem(
      "store_plus_token",
      token
    );

    showDashboard();

  } catch (error) {
    error.textContent =
      error.message ||
      "حدث خطأ أثناء تسجيل الدخول";
  }
}

function logout() {
  token = null;

  localStorage.removeItem(
    "store_plus_token"
  );

  showLogin();
}

async function api(
  url,
  options = {}
) {
  const headers = {
    ...(options.headers || {}),
    Authorization:
      `Bearer ${token}`,
  };

  const response =
    await fetch(
      `${API}${url}`,
      {
        ...options,
        headers,
      }
    );

  if (
    response.status === 401 ||
    response.status === 403
  ) {
    logout();
    throw new Error(
      "انتهت جلسة الدخول"
    );
  }

  return response;
}

/* =========================
   Stats
========================= */

async function loadStats() {
  try {
    const response =
      await api(
        "/api/admin/stats"
      );

    const data =
      await response.json();

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

  } catch (error) {
    console.error(error);
  }
}

/* =========================
   Add App
========================= */

document
  .getElementById("addAppForm")
  ?.addEventListener(
    "submit",
    async (event) => {
      event.preventDefault();

      const message =
        document.getElementById(
          "appMessage"
        );

      const ipa =
        document.getElementById(
          "appIPA"
        ).files[0];

      if (!ipa) {
        message.textContent =
          "اختر ملف IPA أولاً.";

        return;
      }

      if (
        !ipa.name
          .toLowerCase()
          .endsWith(".ipa")
      ) {
        message.textContent =
          "الملف يجب أن يكون بصيغة IPA.";

        return;
      }

      const form =
        document.getElementById(
          "addAppForm"
        );

      const data =
        new FormData(form);

      data.set(
        "featured",
        document.getElementById(
          "appFeatured"
        ).checked
          ? "true"
          : "false"
      );

      message.textContent =
        "جاري رفع التطبيق...";

      try {
        const response =
          await api(
            "/api/admin/apps",
            {
              method: "POST",
              body: data,
            }
          );

        const result =
          await response.json();

        if (!response.ok) {
          throw new Error(
            result.error ||
              "فشل إضافة التطبيق"
          );
        }

        message.textContent =
          "تم رفع التطبيق وإضافته بنجاح.";

        form.reset();

        await loadStats();
        await loadApps();

      } catch (error) {
        console.error(error);

        message.textContent =
          error.message ||
          "حدث خطأ أثناء رفع التطبيق";
      }
    }
  );

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
    const response =
      await api(
        "/api/apps"
      );

    const apps =
      await response.json();

    if (!apps.length) {
      list.textContent =
        "لا توجد تطبيقات.";
      return;
    }

    list.innerHTML =
      apps
        .map(
          (app) => `
            <div class="app-item">

              <strong>
                ${escapeHTML(app.name)}
              </strong>

              <span>
                الإصدار:
                ${escapeHTML(app.version)}
              </span>

              <span>
                التصنيف:
                ${escapeHTML(app.category)}
              </span>

              <span>
                IPA:
                ${
                  app.hasIPA
                    ? "متوفر"
                    : "غير موجود"
                }
              </span>

              ${
                app.hasIPA
                  ? `
                    <a
                      href="/api/apps/${app.id}/ipa"
                      target="_blank"
                    >
                      تحميل IPA
                    </a>
                  `
                  : ""
              }

            </div>
          `
        )
        .join("");

  } catch (error) {
    console.error(error);

    list.textContent =
      "تعذر تحميل التطبيقات.";
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
    const response =
      await api(
        "/api/admin/users"
      );

    const users =
      await response.json();

    if (!users.length) {
      list.textContent =
        "لا يوجد مستخدمون.";
      return;
    }

    list.innerHTML =
      users
        .map(
          (user) => `
            <div class="user-item">
              <strong>
                ${escapeHTML(user.name || user.username)}
              </strong>

              <span>
                ${escapeHTML(user.username)}
              </span>

              <span>
                الشهادة:
                ${
                  user.hasCertificate
                    ? "مرتبطة"
                    : "غير مرتبطة"
                }
              </span>
            </div>
          `
        )
        .join("");

  } catch (error) {
    console.error(error);

    list.textContent =
      "تعذر تحميل المستخدمين.";
  }
}

/* =========================
   Security
========================= */

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* =========================
   Startup
========================= */

if (token) {
  showDashboard();
} else {
  showLogin();
}


