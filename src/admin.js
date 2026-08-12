let token = localStorage.getItem("store_plus_admin_token");

const $ = (id) => document.getElementById(id);

function showDashboard() {
  $("loginPage").classList.add("hidden");
  $("dashboard").classList.remove("hidden");

  loadStats();
  loadApps();
  loadUsers();
}

function showLogin() {
  $("loginPage").classList.remove("hidden");
  $("dashboard").classList.add("hidden");
}

async function login() {
  const username = $("username").value.trim();
  const password = $("password").value;

  $("loginError").textContent = "";

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        username,
        password
      })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "فشل تسجيل الدخول");
    }

    if (data.user?.role !== "admin") {
      throw new Error("هذا الحساب ليس مديرًا");
    }

    token = data.token;

    localStorage.setItem(
      "store_plus_admin_token",
      token
    );

    showDashboard();

  } catch (error) {
    $("loginError").textContent = error.message;
  }
}

function logout() {
  localStorage.removeItem(
    "store_plus_admin_token"
  );

  token = null;

  showLogin();
}

async function api(url, options = {}) {
  options.headers = {
    ...(options.headers || {}),
    Authorization: `Bearer ${token}`
  };

  const response = await fetch(url, options);

  if (response.status === 401) {
    logout();
    throw new Error("انتهت جلسة الدخول");
  }

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.error || "حدث خطأ في الطلب"
    );
  }

  return data;
}

async function loadStats() {
  try {
    const data = await api("/api/admin/stats");

    $("usersCount").textContent = data.users;
    $("appsCount").textContent = data.apps;
    $("downloadsCount").textContent = data.downloads;
    $("jobsCount").textContent = data.installJobs;

  } catch (error) {
    console.error(error);
  }
}

async function loadApps() {
  const container = $("appsList");

  try {
    const apps = await fetch("/api/apps")
      .then(r => r.json());

    if (!apps.length) {
      container.innerHTML =
        "<p>لا توجد تطبيقات حاليًا.</p>";
      return;
    }

    container.innerHTML = apps.map(app => `
      <div class="app">
        <strong>${escapeHtml(app.name)}</strong>

        <div class="meta">
          الإصدار: ${escapeHtml(app.version || "-")}
        </div>

        <div class="meta">
          التصنيف: ${escapeHtml(app.category || "-")}
        </div>

        <div class="meta">
          ${escapeHtml(app.description || "")}
        </div>
      </div>
    `).join("");

  } catch (error) {
    container.textContent =
      "تعذر تحميل التطبيقات";
  }
}

async function loadUsers() {
  const container = $("usersList");

  try {
    const users = await api("/api/admin/users");

    if (!users.length) {
      container.innerHTML =
        "<p>لا يوجد مستخدمون.</p>";
      return;
    }

    container.innerHTML = users.map(user => `
      <div class="user">
        <strong>${escapeHtml(user.name || user.username)}</strong>

        <div class="meta">
          اسم المستخدم: ${escapeHtml(user.username)}
        </div>

        <div class="meta">
          الصلاحية: ${escapeHtml(user.role)}
        </div>

        <div class="meta">
          الشهادة:
          ${user.hasCertificate ? "موجودة" : "غير موجودة"}
        </div>
      </div>
    `).join("");

  } catch (error) {
    container.textContent =
      "تعذر تحميل المستخدمين";
  }
}

async function addApp() {
  $("appMessage").textContent = "";

  const name = $("appName").value.trim();
  const version = $("appVersion").value.trim();
  const category = $("appCategory").value.trim();
  const iconURL = $("appIcon").value.trim();
  const description = $("appDescription").value.trim();
  const featured = $("appFeatured").checked;

  if (!name || !version) {
    $("appMessage").className = "error";
    $("appMessage").textContent =
      "اسم التطبيق والإصدار مطلوبان";
    return;
  }

  try {
    await api("/api/admin/apps", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name,
        version,
        category,
        iconURL,
        description,
        featured
      })
    });

    $("appMessage").className = "success";
    $("appMessage").textContent =
      "تمت إضافة التطبيق بنجاح";

    $("appName").value = "";
    $("appVersion").value = "";
    $("appCategory").value = "";
    $("appIcon").value = "";
    $("appDescription").value = "";
    $("appFeatured").checked = false;

    await loadApps();
    await loadStats();

  } catch (error) {
    $("appMessage").className = "error";
    $("appMessage").textContent =
      error.message;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

if (token) {
  showDashboard();
} else {
  showLogin();
}
