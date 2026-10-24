const configuredApiUrl = document.querySelector('meta[name="trustvault-api-base"]')?.content.trim();
const isLocalFrontend = ["127.0.0.1", "localhost"].includes(window.location.hostname)
  && window.location.port === "8001";
const API_BASE_URL = (configuredApiUrl
  || (isLocalFrontend
    ? `${window.location.protocol}//${window.location.hostname}:8000`
    : window.location.origin)).replace(/\/$/, "");
const ACCESS_TOKEN_KEY = "trustvault_access_token";
const TOKEN_EXPIRY_KEY = "trustvault_token_expiry";
let refreshOpenNotificationPanel = null;

document.addEventListener("DOMContentLoaded", () => {
  const protectedPage = Boolean(document.querySelector("[data-authenticated-page]"));
  const authenticationCheck = initializeAuthenticationVisibility();
  initializeLandingNavigation();
  initializeSidebar();
  initializePasswordToggle();
  initializeProfileControls();
  initializeLogoutLinks();
  initializeLoginForm();
  initializeRegistrationForm();
  initializePasswordReset();
  initializeGoogleSignIn();
  initializeGoogleOAuthCallback();
  if (protectedPage) {
    authenticationCheck.then((isAuthenticated) => {
      if (!isAuthenticated) return;
      initializeTheme();
      initializePageFeatures();
    });
    return;
  }
  initializeTheme();
  initializePageFeatures();
});

window.addEventListener("pageshow", (event) => {
  if (event.persisted) initializeAuthenticationVisibility();
});

class AuthenticationError extends Error {}

async function apiRequest(path, options = {}) {
  if (window.location.protocol === "file:") {
    throw new Error(
      "TrustVault was opened directly from disk. Run `python -m http.server 8001` from the project root, then open http://127.0.0.1:8001/app/templates/login.html.",
    );
  }

  const headers = new Headers(options.headers || {});
  const token = getAccessToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
      credentials: "omit",
    });
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error("Cannot reach the TrustVault API. Check the server address and try again.");
    }
    throw error;
  }

  if (response.status === 401) {
    clearAccessToken();
    setAuthenticationVisibility(null);
    if (document.querySelector("[data-authenticated-page]")) {
      window.location.replace("login.html");
    }
    throw new AuthenticationError("Your sign-in session is missing or has expired. Sign in again.");
  }
  if (!response.ok) {
    let detail = `Request failed (${response.status}).`;
    try {
      const payload = await response.json();
      if (typeof payload.detail === "string") detail = payload.detail;
      else if (Array.isArray(payload.detail)) {
        detail = payload.detail.map((item) => item.msg || "Invalid request.").join(" ");
      }
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
    }
    throw new Error(detail);
  }
  return response;
}

async function apiJson(path, options = {}) {
  const response = await apiRequest(path, options);
  if (response.status === 204) return null;
  return response.json();
}

function getAccessToken() {
  const token = sessionStorage.getItem(ACCESS_TOKEN_KEY);
  const expiresAt = Number(sessionStorage.getItem(TOKEN_EXPIRY_KEY) || 0);
  if (token && expiresAt > Date.now()) return token;
  if (token) clearAccessToken();
  return null;
}

function setAccessToken(token, expiresIn) {
  sessionStorage.setItem(ACCESS_TOKEN_KEY, token);
  sessionStorage.setItem(TOKEN_EXPIRY_KEY, String(Date.now() + expiresIn * 1000));
}

function clearAccessToken() {
  sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  sessionStorage.removeItem(TOKEN_EXPIRY_KEY);
}

function setAuthenticationVisibility(user) {
  const authenticated = Boolean(user);
  const protectedPage = document.querySelector("[data-authenticated-page]");
  if (!authenticated && protectedPage) protectedPage.hidden = true;
  document.querySelectorAll("[data-authenticated-only]").forEach((element) => {
    element.hidden = !authenticated;
  });
  document.querySelectorAll("[data-public-only]").forEach((element) => {
    element.hidden = authenticated;
  });
  document.querySelectorAll("[data-admin-only]").forEach((element) => {
    element.hidden = !authenticated || user.role !== "admin";
  });
  const navigation = document.querySelector(".side-nav");
  let adminLink = document.querySelector("[data-admin-navigation]");
  if (user?.role === "admin" && navigation && !adminLink) {
    adminLink = document.createElement("a");
    adminLink.className = "side-nav-link";
    adminLink.href = "admin.html";
    adminLink.dataset.adminNavigation = "true";
    adminLink.textContent = "Admin dashboard";
    navigation.append(adminLink);
  } else if (user?.role !== "admin") {
    adminLink?.remove();
  }
}

function initializeAuthenticationVisibility() {
  const protectedPage = document.querySelector("[data-authenticated-page]");
  if (protectedPage) protectedPage.hidden = true;
  setAuthenticationVisibility(null);

  const token = getAccessToken();
  if (!token) {
    if (protectedPage) window.location.replace("login.html");
    return Promise.resolve(false);
  }

  return apiJson("/api/auth/me", { cache: "no-store" }).then((user) => {
    if (getAccessToken() !== token) return false;
    setAuthenticationVisibility(user);
    if (document.body.hasAttribute("data-auth-redirect")) {
      window.location.replace("dashboard.html");
      return false;
    }
    if (protectedPage?.hasAttribute("data-admin-page") && user.role !== "admin") {
      window.location.replace("dashboard.html");
      return false;
    }
    if (protectedPage) protectedPage.hidden = false;
    return true;
  }).catch((error) => {
    setAuthenticationVisibility(null);
    if (protectedPage) {
      window.location.replace("login.html");
    } else if (!(error instanceof AuthenticationError)) {
      console.error("Could not verify the signed-in account.", error);
    }
    return false;
  });
}

function initializePageFeatures() {
  initializeNotifications();
  initializeHelp();
  initializeSettings();
  initializeDocumentPage();
  initializeSharedPage();
  initializePermissionsPage();
  initializeAuditPage();
  initializeAdminDashboard();
  initializeDashboard();
}

function showStatus(element, message, isError = false) {
  if (!element) return;
  element.textContent = message;
  element.dataset.state = isError ? "error" : "info";
}

function errorMessage(error) {
  return error instanceof Error ? error.message : "An unexpected error occurred.";
}

function showTableState(tbody, columnCount, message, isError = false) {
  if (!tbody) return;
  tbody.replaceChildren();
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = columnCount;
  cell.textContent = message;
  if (isError) cell.dataset.state = "error";
  row.append(cell);
  tbody.append(row);
}

async function loadProfile() {
  const user = await apiJson("/api/auth/me", { cache: "no-store" });
  const displayName = typeof user.display_name === "string" && user.display_name.trim()
    ? user.display_name.trim()
    : "";
  const profileLabel = displayName || user.email || "User";
  const initials = profileLabel
    .split("@")[0]
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("");
  document.querySelectorAll("[data-user-email], .sidebar-profile .profile-copy strong, .topbar-profile .profile-copy strong")
    .forEach((element) => { element.textContent = profileLabel; });
  document.querySelectorAll(".sidebar-profile .profile-copy small, .topbar-profile .profile-copy small")
    .forEach((element) => { element.textContent = user.email || "Email unavailable"; });
  document.querySelectorAll("[data-user-initials], .sidebar-profile .profile-avatar, .topbar-profile .profile-avatar")
    .forEach((element) => { element.textContent = initials || "TV"; });
  document.querySelectorAll("[data-profile-name]")
    .forEach((element) => { element.textContent = displayName || "User"; });
  document.querySelectorAll("[data-profile-email]")
    .forEach((element) => { element.textContent = user.email || "Email unavailable"; });
  const nameInput = document.querySelector("[data-profile-name-input]");
  const emailInput = document.querySelector("[data-profile-email-input]");
  const idInput = document.querySelector("[data-profile-id]");
  if (nameInput) nameInput.value = displayName;
  if (emailInput) emailInput.value = user.email || "";
  if (idInput) idInput.value = Number.isInteger(user.id) ? String(user.id) : "Unavailable";
  return user;
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme === "dark" ? "dark" : "light";
}

function initializeTheme() {
  const lastUserId = localStorage.getItem("trustvault_last_user_id");
  const savedTheme = lastUserId
    ? localStorage.getItem(`trustvault_theme_${lastUserId}`)
    : null;
  applyTheme(savedTheme);
  if (getAccessToken()) {
    loadUserPreferences().catch((error) => {
      const status = document.querySelector("[data-settings-status]");
      if (status) showStatus(status, errorMessage(error), true);
    });
  }
}

async function loadUserPreferences() {
  const preferences = await apiJson("/api/auth/preferences", { cache: "no-store" });
  localStorage.setItem("trustvault_last_user_id", String(preferences.user_id));
  localStorage.setItem(`trustvault_theme_${preferences.user_id}`, preferences.theme);
  applyTheme(preferences.theme);
  return preferences;
}

function initializeProfileControls() {
  document.querySelectorAll(".profile-button").forEach((button) => {
    button.setAttribute("role", "button");
    button.setAttribute("aria-haspopup", "dialog");
    button.setAttribute("aria-label", "Open your profile");
    button.addEventListener("click", (event) => {
      event.preventDefault();
      openProfileDialog();
    });
    button.addEventListener("keydown", (event) => {
      if (event.key === " ") {
        event.preventDefault();
        openProfileDialog();
      }
    });
  });
}

function openProfileDialog() {
  const content = document.createElement("div");
  content.className = "profile-dialog-content";
  const status = document.createElement("p");
  status.className = "profile-dialog-status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const account = document.createElement("div");
  account.className = "profile-dialog-account";
  const avatar = document.createElement("span");
  avatar.className = "profile-avatar profile-dialog-avatar";
  avatar.textContent = "TV";
  const identity = document.createElement("span");
  const name = document.createElement("strong");
  const email = document.createElement("small");
  identity.append(name, email);
  account.append(avatar, identity);
  const role = document.createElement("p");
  role.className = "profile-dialog-role";
  const accountDetails = document.createElement("p");
  accountDetails.className = "profile-dialog-details";

  const signIn = document.createElement("a");
  signIn.className = "button button-primary";
  signIn.href = "login.html";
  signIn.textContent = "Sign in";
  const signOut = document.createElement("button");
  signOut.type = "button";
  signOut.className = "button button-secondary profile-sign-out";
  signOut.textContent = "Sign out";
  signOut.addEventListener("click", () => logoutCurrentUser("login.html"));

  const form = document.createElement("form");
  form.className = "profile-edit-form";
  const label = document.createElement("label");
  label.textContent = "Display name";
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.name = "display_name";
  nameInput.maxLength = 100;
  nameInput.autocomplete = "name";
  label.append(nameInput);
  const save = document.createElement("button");
  save.type = "submit";
  save.className = "button button-primary";
  save.textContent = "Save name";
  form.append(label, save);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const user = await apiJson("/api/auth/me", {
        method: "PATCH",
        cache: "no-store",
        body: JSON.stringify({ display_name: nameInput.value.trim() }),
      });
      await loadProfile();
      const labelText = user.display_name || user.email || "User";
      name.textContent = labelText;
      nameInput.value = user.display_name || "";
      avatar.textContent = initialsFor(labelText);
      showStatus(status, "Profile name updated.");
    } catch (error) {
      showStatus(status, errorMessage(error), true);
    } finally {
      save.disabled = false;
    }
  });

  const actions = document.createElement("div");
  actions.className = "profile-dialog-actions";
  actions.append(signIn, signOut);
  content.append(account, role, accountDetails, form, status, actions);
  openInformationDialog("Your profile", content);
  const authenticated = Boolean(getAccessToken());
  form.hidden = !authenticated;
  signOut.hidden = !authenticated;
  signIn.hidden = authenticated;
  if (!authenticated) {
    name.textContent = "Signed out";
    email.textContent = "Sign in to view your account.";
    role.textContent = "No account is currently signed in.";
    accountDetails.textContent = "";
    status.textContent = "";
    return;
  }
  showStatus(status, "Loading account information…");
  Promise.all([
    apiJson("/api/auth/me", { cache: "no-store" }),
    apiJson("/api/documents"),
    apiJson("/api/documents/shared-with-me"),
  ]).then(([user, ownedDocuments, sharedDocuments]) => {
    const displayName = user.display_name || "";
    const labelText = displayName || user.email || "User";
    name.textContent = labelText;
    email.textContent = user.email || "Email unavailable";
    avatar.textContent = initialsFor(labelText);
    nameInput.value = displayName;
    const accountRole = user.role === "admin" ? "Admin" : "User";
    role.textContent = `${accountRole} account · Owner of ${ownedDocuments.length} document(s) · Viewer on ${sharedDocuments.length} shared document(s)`;
    accountDetails.textContent = `Account ID: ${user.id} · Registered ${formatDate(user.created_at)}`;
    status.textContent = "";
  }).catch((error) => {
    if (!getAccessToken()) {
      name.textContent = "Signed out";
      email.textContent = "Sign in to view your account.";
      role.textContent = "Your session has expired. Sign in again to view account details.";
      accountDetails.textContent = "";
      form.hidden = true;
      signOut.hidden = true;
      signIn.hidden = false;
    }
    showStatus(status, errorMessage(error), true);
  });
}

function initialsFor(value) {
  return value
    .split("@")[0]
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("") || "TV";
}

function openInformationDialog(titleText, content) {
  const dialog = document.createElement("dialog");
  dialog.className = "information-dialog";
  const heading = document.createElement("h2");
  heading.id = "information-dialog-title";
  heading.textContent = titleText;
  dialog.setAttribute("aria-labelledby", heading.id);
  const close = document.createElement("button");
  close.type = "button";
  close.className = "icon-button information-dialog-close";
  close.setAttribute("aria-label", "Close");
  close.textContent = "×";
  close.addEventListener("click", () => dialog.close());
  const header = document.createElement("div");
  header.className = "information-dialog-header";
  header.append(heading, close);
  dialog.append(header, content);
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => dialog.remove(), { once: true });
  document.body.append(dialog);
  dialog.showModal();
  close.focus();
}

function initializeNotifications() {
  document.querySelectorAll(".notification-button").forEach((button) => {
    let badge = button.querySelector(".notification-count");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "notification-count";
      badge.hidden = true;
      button.append(badge);
    }
    button.addEventListener("click", async () => {
      const dialog = document.createElement("dialog");
      dialog.className = "information-dialog notification-dialog";
      const heading = document.createElement("h2");
      heading.id = "notification-dialog-title";
      heading.textContent = "Notifications";
      dialog.setAttribute("aria-labelledby", heading.id);
      const close = document.createElement("button");
      close.type = "button";
      close.className = "icon-button information-dialog-close";
      close.setAttribute("aria-label", "Close");
      close.textContent = "×";
      const header = document.createElement("div");
      header.className = "information-dialog-header";
      header.append(heading, close);
      const list = document.createElement("div");
      list.className = "notification-list";
      const status = document.createElement("p");
      status.className = "information-dialog-empty";
      status.setAttribute("role", "status");
      status.textContent = "Loading notifications…";
      dialog.append(header, status, list);
      close.addEventListener("click", () => dialog.close());
      dialog.addEventListener("click", (event) => {
        if (event.target === dialog) dialog.close();
      });
      dialog.addEventListener("close", () => {
        if (refreshOpenNotificationPanel === renderNotifications) {
          refreshOpenNotificationPanel = null;
        }
        dialog.remove();
      }, { once: true });
      document.body.append(dialog);
      dialog.showModal();

      const renderNotifications = async () => {
        status.hidden = true;
        list.replaceChildren();
        try {
          const payload = await apiJson("/api/notifications", { cache: "no-store" });
          updateNotificationBadge(
            payload.notifications_enabled ? payload.unread_count : 0,
          );
          updateNotificationSummary(payload);
          if (!payload.items.length) {
            status.hidden = false;
            status.textContent = "No notifications yet.";
            return;
          }
          payload.items.forEach((notification) => {
            const card = document.createElement("article");
            card.className = "notification-card";
            card.dataset.read = String(Boolean(notification.read_at));
            const message = document.createElement("p");
            const owner = notification.owner_name || "User";
            const documentName = notification.document_name || "Document";
            message.textContent = `Document shared with you — ${owner} shared "${documentName}" with you.`;
            const detail = document.createElement("p");
            detail.className = "notification-detail";
            const accessType = notification.access_level === "read" ? "Read only" : "Access unavailable";
            detail.textContent = `${accessType} · ${formatDate(notification.created_at)}`;
            const state = document.createElement("span");
            state.className = "notification-state";
            state.textContent = notification.read_at ? "Read" : "Unread";
            const actions = document.createElement("div");
            actions.className = "notification-actions";
            const open = document.createElement("button");
            open.type = "button";
            open.className = "button button-primary button-small";
            open.textContent = "Open Shared With Me";
            open.addEventListener("click", async () => {
              open.disabled = true;
              try {
                if (!notification.read_at) {
                  await apiJson(`/api/notifications/${notification.id}/read`, { method: "POST" });
                }
                await refreshNotificationCount();
                window.location.assign("shared.html");
              } catch (error) {
                showStatus(status, errorMessage(error), true);
                status.hidden = false;
                open.disabled = false;
              }
            });
            const dismiss = document.createElement("button");
            dismiss.type = "button";
            dismiss.className = "button button-secondary button-small";
            dismiss.textContent = "Dismiss";
            dismiss.addEventListener("click", async () => {
              dismiss.disabled = true;
              try {
                await apiJson(`/api/notifications/${notification.id}`, { method: "DELETE" });
                await renderNotifications();
              } catch (error) {
                showStatus(status, errorMessage(error), true);
                status.hidden = false;
                dismiss.disabled = false;
              }
            });
            actions.append(open, dismiss);
            card.append(message, detail, state, actions);
            list.append(card);
          });
        } catch (error) {
          status.hidden = false;
          showStatus(status, errorMessage(error), true);
        }
      };
      refreshOpenNotificationPanel = renderNotifications;
      await renderNotifications();
    });
  });
  refreshNotificationCount();
  window.addEventListener("focus", refreshNotificationCount);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") refreshNotificationCount();
  });
  window.setInterval(refreshNotificationCount, 30000);
}

function updateNotificationBadge(count) {
  document.querySelectorAll(".notification-button").forEach((button) => {
    const badge = button.querySelector(".notification-count");
    if (!badge) return;
    const unread = Number.isInteger(count) ? Math.max(0, count) : 0;
    badge.textContent = unread > 99 ? "99+" : String(unread);
    badge.hidden = unread === 0;
    button.setAttribute("aria-label", unread ? `Notifications, ${unread} unread` : "Notifications");
  });
}

function updateNotificationSummary(payload) {
  const total = document.querySelector("[data-notification-total]");
  const unread = document.querySelector("[data-notification-unread]");
  if (total) total.textContent = String(payload.total_count);
  if (unread) unread.textContent = String(payload.unread_count);
}

async function refreshNotificationCount() {
  if (!getAccessToken()) {
    updateNotificationBadge(0);
    return;
  }
  try {
    const payload = await apiJson("/api/notifications", { cache: "no-store" });
    updateNotificationBadge(
      payload.notifications_enabled ? payload.unread_count : 0,
    );
    updateNotificationSummary(payload);
    if (refreshOpenNotificationPanel) await refreshOpenNotificationPanel();
  } catch (error) {
    document.querySelectorAll(".notification-button").forEach((button) => {
      button.dataset.notificationError = errorMessage(error);
    });
  }
}

function initializeHelp() {
  document.querySelectorAll(".support-card").forEach((trigger) => {
    trigger.setAttribute("role", "button");
    trigger.setAttribute("tabindex", "0");
    trigger.setAttribute("aria-label", "Open TrustVault help");
    const openHelp = () => {
      const content = document.createElement("div");
      content.className = "help-content";
      [
        ["Google sign-in and switching accounts", "Choose Continue with Google when configured, or sign in with your registered email and password. To switch accounts, sign out first, then sign in with the other account."],
        ["Upload a document", "Open My Documents, choose a file, then select Upload document."],
        ["Share a document", "For a document you own, choose Share and enter the registered recipient's email or user ID. Access is read-only."],
        ["Read-only access", "A viewer can download an active shared document but cannot manage permissions or become its owner."],
        ["Find and download shared documents", "Open Shared With Me to see active shares. Use Download; the server checks access each time."],
        ["Revoke access", "Open Permissions and select Revoke next to the active grant. The recipient immediately loses access and cannot download the document afterward."],
        ["Notifications", "A share creates a private notification for its recipient. The bell shows unread alerts; open one to go to Shared With Me, or dismiss it."],
        ["Troubleshooting", "If a page says your session is missing or expired, sign in again. If the API cannot be reached, check that the backend is running at 127.0.0.1:8000."],
      ].forEach(([title, description]) => {
        const section = document.createElement("section");
        const heading = document.createElement("h3");
        heading.textContent = title;
        const paragraph = document.createElement("p");
        paragraph.textContent = description;
        section.append(heading, paragraph);
        content.append(section);
      });
      openInformationDialog("TrustVault help", content);
    };
    trigger.addEventListener("click", openHelp);
    trigger.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openHelp();
      }
    });
  });
}

function initializeSettings() {
  if (!document.querySelector("[data-profile-name]")) return;
  const saveProfile = document.querySelector("[data-profile-save]");
  const nameInput = document.querySelector("[data-profile-name-input]");
  if (saveProfile) saveProfile.disabled = !getAccessToken();
  if (nameInput) nameInput.disabled = !getAccessToken();
  loadProfile().catch((error) => {
    const status = document.querySelector("[data-settings-status]");
    showStatus(status, errorMessage(error), true);
    if (saveProfile) saveProfile.disabled = true;
    if (nameInput) nameInput.disabled = true;
  });
  const status = document.querySelector("[data-settings-status]");
  if (saveProfile && nameInput && getAccessToken()) {
    saveProfile.disabled = false;
    nameInput.disabled = false;
  }
  if (saveProfile && nameInput) {
    saveProfile.addEventListener("click", async () => {
      saveProfile.disabled = true;
      try {
        await apiJson("/api/auth/me", {
          method: "PATCH",
          cache: "no-store",
          body: JSON.stringify({ display_name: nameInput.value.trim() }),
        });
        await loadProfile();
        showStatus(status, "Display name saved.");
      } catch (error) {
        showStatus(status, errorMessage(error), true);
      } finally {
        saveProfile.disabled = false;
      }
    });
  }
  initializePreferenceControls();
}

function initializePreferenceControls() {
  const status = document.querySelector("[data-settings-status]");
  const notificationsToggle = document.querySelector("[data-notifications-toggle]");
  const themeToggle = document.querySelector("[data-theme-toggle]");

  const load = async () => {
    const [preferences, notifications] = await Promise.all([
      loadUserPreferences(),
      apiJson("/api/notifications", { cache: "no-store" }),
    ]);
    if (notificationsToggle) notificationsToggle.checked = preferences.notifications_enabled;
    if (themeToggle) themeToggle.checked = preferences.theme === "dark";
    if (notificationsToggle) notificationsToggle.disabled = !getAccessToken();
    if (themeToggle) themeToggle.disabled = !getAccessToken();
    updateNotificationSummary(notifications);
    showStatus(status, "Preferences loaded for your account.");
  };
  load().catch((error) => {
    if (notificationsToggle) notificationsToggle.disabled = true;
    if (themeToggle) themeToggle.disabled = true;
    showStatus(status, errorMessage(error), true);
  });

  if (notificationsToggle) {
    notificationsToggle.addEventListener("change", async () => {
      const previousEnabled = !notificationsToggle.checked;
      let preferenceSaved = false;
      notificationsToggle.disabled = true;
      try {
        const preferences = await apiJson("/api/auth/preferences", {
          method: "PATCH",
          cache: "no-store",
          body: JSON.stringify({ notifications_enabled: notificationsToggle.checked }),
        });
        preferenceSaved = true;
        notificationsToggle.checked = preferences.notifications_enabled;
        const notifications = await apiJson("/api/notifications", { cache: "no-store" });
        updateNotificationSummary(notifications);
        updateNotificationBadge(
          preferences.notifications_enabled ? notifications.unread_count : 0,
        );
        showStatus(
          status,
          preferences.notifications_enabled ? "Notifications are on." : "Notification alerts are off.",
        );
      } catch (error) {
        if (!preferenceSaved) notificationsToggle.checked = previousEnabled;
        showStatus(status, errorMessage(error), true);
      } finally {
        notificationsToggle.disabled = !getAccessToken();
      }
    });
  }

  if (themeToggle) {
    themeToggle.addEventListener("change", async () => {
      const theme = themeToggle.checked ? "dark" : "light";
      const previousTheme = themeToggle.checked ? "light" : "dark";
      themeToggle.disabled = true;
      applyTheme(theme);
      try {
        const preferences = await apiJson("/api/auth/preferences", {
          method: "PATCH",
          cache: "no-store",
          body: JSON.stringify({ theme }),
        });
        localStorage.setItem("trustvault_last_user_id", String(preferences.user_id));
        localStorage.setItem(`trustvault_theme_${preferences.user_id}`, preferences.theme);
        applyTheme(preferences.theme);
        showStatus(status, `${preferences.theme === "dark" ? "Dark" : "Light"} theme saved.`);
      } catch (error) {
        themeToggle.checked = previousTheme === "dark";
        applyTheme(previousTheme);
        showStatus(status, errorMessage(error), true);
      } finally {
        themeToggle.disabled = !getAccessToken();
      }
    });
  }
}

function initializeLandingNavigation() {
  const mobileMenu = document.querySelector(".landing-menu-toggle");
  const landingNav = document.querySelector("#landing-nav");
  if (!mobileMenu || !landingNav) return;

  mobileMenu.addEventListener("click", () => {
    const isOpen = mobileMenu.getAttribute("aria-expanded") === "true";
    mobileMenu.setAttribute("aria-expanded", String(!isOpen));
    mobileMenu.setAttribute("aria-label", isOpen ? "Open navigation" : "Close navigation");
    landingNav.classList.toggle("is-open", !isOpen);
  });
  landingNav.addEventListener("click", (event) => {
    if (event.target instanceof Element && event.target.closest("a")) {
      mobileMenu.setAttribute("aria-expanded", "false");
      mobileMenu.setAttribute("aria-label", "Open navigation");
      landingNav.classList.remove("is-open");
    }
  });
}

function initializeSidebar() {
  const toggle = document.querySelector(".sidebar-toggle");
  const backdrop = document.querySelector("[data-sidebar-close]");
  const page = document.querySelector(".dashboard-page");
  if (!toggle || !backdrop || !page) return;

  const setOpen = (isOpen) => {
    page.classList.toggle("sidebar-open", isOpen);
    toggle.setAttribute("aria-expanded", String(isOpen));
    toggle.setAttribute("aria-label", isOpen ? "Close navigation" : "Open navigation");
  };
  toggle.addEventListener("click", () => setOpen(toggle.getAttribute("aria-expanded") !== "true"));
  backdrop.addEventListener("click", () => setOpen(false));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setOpen(false);
  });
}

function initializePasswordToggle() {
  document.querySelectorAll("[data-password-toggle]").forEach((toggle) => {
    const input = toggle.closest(".password-input-wrap")?.querySelector("input");
    if (!input) return;

    toggle.addEventListener("click", () => {
      const isVisible = input.type === "text";
      input.type = isVisible ? "password" : "text";
      toggle.setAttribute("aria-pressed", String(!isVisible));
      toggle.setAttribute("aria-label", isVisible ? "Show password" : "Hide password");
    });
  });
}

function initializeLogoutLinks() {
  document.querySelectorAll('a[href="login.html"]').forEach((link) => {
    if (link.matches("[data-logout], .profile-button")) return;
    link.addEventListener("click", () => clearAccessToken());
  });
  document.querySelectorAll("[data-logout]").forEach((link) => {
    link.addEventListener("click", async (event) => {
      event.preventDefault();
      await logoutCurrentUser(link.href);
    });
  });
}

async function logoutCurrentUser(destination = "login.html") {
  const logoutRequest = getAccessToken()
    ? apiJson("/api/auth/logout", { method: "POST" })
    : Promise.resolve(null);
  clearAccessToken();
  setAuthenticationVisibility(null);
  try {
    await logoutRequest;
  } catch (error) {
    if (!(error instanceof AuthenticationError)) {
      console.error("Logout activity could not be recorded.", error);
    }
  } finally {
    clearAccessToken();
    window.location.assign(destination);
  }
}

function initializeLoginForm() {
  const form = document.querySelector("[data-api-login]");
  const status = document.querySelector("[data-login-status]");
  if (status && new URLSearchParams(window.location.search).get("registered") === "1") {
    showStatus(status, "Account created successfully. Please sign in.");
  }
  if (!form || !status) return;

  form.querySelectorAll("input").forEach((input) => {
    input.addEventListener("input", () => {
      if (status.dataset.state === "error") showStatus(status, "");
    });
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    const emailInput = form.elements.namedItem("email");
    const passwordInput = form.elements.namedItem("password");
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    if (!email || !password) {
      showStatus(
        status,
        !email && !password
          ? "Enter your email address and password."
          : !email
            ? "Enter your email address."
            : "Enter your password.",
        true,
      );
      (!email ? emailInput : passwordInput).focus();
      return;
    }
    if (!emailInput.validity.valid) {
      showStatus(status, "Enter a valid email address.", true);
      emailInput.focus();
      return;
    }
    submit.disabled = true;
    showStatus(status, "Signing in…");

    try {
      clearAccessToken();
      const token = await apiJson("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      setAccessToken(token.access_token, token.expires_in);
      form.reset();
      showStatus(status, "");
      window.location.assign("dashboard.html");
    } catch (error) {
      showStatus(
        status,
        error instanceof AuthenticationError
          || (error instanceof Error && error.message === "Invalid email or password.")
          ? "Invalid email or password."
          : errorMessage(error),
        true,
      );
    } finally {
      submit.disabled = false;
    }
  });
}

function initializeRegistrationForm() {
  const form = document.querySelector("[data-api-register]");
  const status = document.querySelector("[data-register-status]");
  if (!form || !status) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    const emailInput = form.elements.namedItem("email");
    const passwordInput = form.elements.namedItem("password");
    const confirmationInput = form.elements.namedItem("confirm_password");
    const displayNameInput = form.elements.namedItem("display_name");
    if (
      !(emailInput instanceof HTMLInputElement)
      || !(passwordInput instanceof HTMLInputElement)
      || !(confirmationInput instanceof HTMLInputElement)
      || !(submit instanceof HTMLButtonElement)
    ) {
      showStatus(status, "The registration form is incomplete. Refresh the page and try again.", true);
      return;
    }
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmation = confirmationInput.value;
    const displayName = displayNameInput instanceof HTMLInputElement
      ? displayNameInput.value.trim()
      : "";
    if (password !== confirmation) {
      showStatus(status, "The passwords do not match.", true);
      confirmationInput.focus();
      return;
    }

    submit.disabled = true;
    showStatus(status, "Creating your account…");
    try {
      await apiJson("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({ email, password, display_name: displayName || null }),
      });
      form.reset();
      showStatus(status, "Account created successfully. Redirecting to sign in.");
      window.setTimeout(() => {
        window.location.assign("login.html?registered=1");
      }, 900);
    } catch (error) {
      showStatus(status, errorMessage(error), true);
    } finally {
      submit.disabled = false;
    }
  });
}

function initializePasswordReset() {
  const requestForm = document.querySelector("[data-password-reset-request]");
  const confirmForm = document.querySelector("[data-password-reset-confirm]");
  if (!requestForm || !confirmForm) return;

  const requestStatus = document.querySelector("[data-password-reset-request-status]");
  const confirmStatus = document.querySelector("[data-password-reset-confirm-status]");
  const token = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
  const tokenInput = document.createElement("input");
  tokenInput.type = "hidden";
  tokenInput.name = "token";
  tokenInput.value = token;
  confirmForm.append(tokenInput);

  if (token) {
    requestForm.hidden = true;
    confirmForm.hidden = false;
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  } else {
    confirmForm.hidden = true;
  }

  requestForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = requestForm.querySelector('button[type="submit"]');
    const email = requestForm.elements.namedItem("email").value.trim();
    submit.disabled = true;
    showStatus(
      requestStatus,
      "If an account exists and email delivery is configured, reset instructions will be sent if delivery succeeds.",
    );
    try {
      await apiJson("/api/auth/password-reset/request", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      requestForm.reset();
    } catch (error) {
      showStatus(requestStatus, errorMessage(error), true);
    } finally {
      submit.disabled = false;
    }
  });

  confirmForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = confirmForm.querySelector('button[type="submit"]');
    const newPassword = confirmForm.elements.namedItem("new_password").value;
    const confirmPassword = confirmForm.elements.namedItem("confirm_password").value;
    if (newPassword !== confirmPassword) {
      showStatus(confirmStatus, "The passwords do not match.", true);
      return;
    }
    if (!token) {
      showStatus(confirmStatus, "Open a valid reset link from your email.", true);
      return;
    }
    submit.disabled = true;
    showStatus(confirmStatus, "Updating your password…");
    try {
      await apiJson("/api/auth/password-reset/confirm", {
        method: "POST",
        body: JSON.stringify({
          token,
          new_password: newPassword,
          confirm_password: confirmPassword,
        }),
      });
      confirmForm.reset();
      tokenInput.value = "";
      showStatus(confirmStatus, "Password reset successfully. You can now sign in.");
    } catch (error) {
      showStatus(confirmStatus, errorMessage(error), true);
    } finally {
      submit.disabled = false;
    }
  });
}

function initializeGoogleSignIn() {
  const button = document.querySelector("[data-google-sign-in]");
  if (!button) return;
  button.addEventListener("click", () => {
    clearAccessToken();
    window.location.assign(`${API_BASE_URL}/api/auth/google/start`);
  });
}

function initializeGoogleOAuthCallback() {
  const status = document.querySelector("[data-login-status]");
  const params = new URLSearchParams(window.location.hash.slice(1));
  const code = params.get("google_code");
  const error = params.get("google_error");
  if (!code && !error) return;

  window.history.replaceState(null, "", window.location.pathname + window.location.search);
  if (!status) return;
  if (error) {
    const messages = {
      not_configured: "Google sign-in is not configured. Use email and password or contact the administrator.",
      invalid_state: "Google sign-in could not be verified. Please try again.",
      cancelled: "Google sign-in was cancelled.",
      callback_failed: "Google sign-in did not complete. Please try again.",
      verification_failed: "Google sign-in could not be verified. Please try again.",
      account_mismatch: "This Google account no longer matches its TrustVault account. Contact support.",
      account_exists: "An account with this email already exists. Sign in with your password.",
      account_conflict: "This Google account could not be linked safely. Try again or contact support.",
    };
    showStatus(status, messages[error] || "Google sign-in failed. Please try again.", true);
    return;
  }

  showStatus(status, "Completing Google sign-in…");
  apiJson("/api/auth/google/exchange", {
    method: "POST",
    body: JSON.stringify({ code }),
  }).then((token) => {
    setAccessToken(token.access_token, token.expires_in);
    window.location.assign("dashboard.html");
  }).catch((requestError) => {
    showStatus(status, errorMessage(requestError), true);
  });
}

function fileExtension(filename) {
  const dot = filename.lastIndexOf(".");
  return dot < 0 ? "" : filename.slice(dot + 1).toUpperCase();
}

function fileIconClass(extension) {
  if (extension === "PDF") return ["file-pdf", "PDF"];
  if (["DOC", "DOCX"].includes(extension)) return ["file-doc", "W"];
  if (["XLS", "XLSX", "CSV"].includes(extension)) return ["file-xls", "X"];
  if (["PNG", "JPG", "JPEG"].includes(extension)) return ["file-image", "▧"];
  return ["file-doc", extension.slice(0, 3) || "FILE"];
}

function fileTypeClass(extension) {
  if (extension === "PDF") return "type-pdf";
  if (["DOC", "DOCX"].includes(extension)) return "type-doc";
  if (["XLS", "XLSX", "CSV"].includes(extension)) return "type-xls";
  if (["PNG", "JPG", "JPEG"].includes(extension)) return "type-image";
  return "type-doc";
}

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Date unavailable";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function createFileCell(documentData) {
  const extension = fileExtension(documentData.filename);
  const [iconClass, iconLabel] = fileIconClass(extension);
  const fileCell = document.createElement("span");
  fileCell.className = "file-cell";
  const icon = document.createElement("span");
  icon.className = `file-icon ${iconClass}`;
  icon.textContent = iconLabel;
  const copy = document.createElement("span");
  const title = document.createElement("strong");
  title.textContent = documentData.title || documentData.filename;
  const filename = document.createElement("small");
  filename.textContent = documentData.filename;
  copy.append(title, filename);
  fileCell.append(icon, copy);
  return fileCell;
}

function downloadButton(documentData, label = "Download") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "button button-secondary";
  button.textContent = label;
  button.setAttribute("aria-label", `Download ${documentData.filename}`);
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const response = await apiRequest(`/api/documents/${encodeURIComponent(documentData.id)}/download`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = documentData.filename;
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      window.alert(errorMessage(error));
    } finally {
      button.disabled = false;
    }
  });
  return button;
}

function shareDocumentButton(documentData) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "button button-secondary button-small";
  button.textContent = "Share";
  button.setAttribute("aria-label", `Share ${documentData.filename}`);
  button.addEventListener("click", () => {
    const dialog = document.createElement("dialog");
    dialog.className = "share-dialog";
    const heading = document.createElement("h2");
    heading.id = "share-dialog-title";
    heading.textContent = `Share ${documentData.title || documentData.filename}`;
    dialog.setAttribute("aria-labelledby", heading.id);

    const description = document.createElement("p");
    description.textContent = "Grant read-only access to a registered TrustVault user.";
    const form = document.createElement("form");
    form.className = "share-dialog-form";
    const recipientLabel = document.createElement("label");
    recipientLabel.textContent = "Recipient email or user ID";
    const recipient = document.createElement("input");
    recipient.type = "text";
    recipient.required = true;
    recipient.maxLength = 254;
    recipient.autocomplete = "off";
    recipient.placeholder = "name@example.com or user ID";
    recipientLabel.append(recipient);

    const accessLabel = document.createElement("label");
    accessLabel.textContent = "Access";
    const access = document.createElement("select");
    access.add(new Option("Read only", "read", true, true));
    accessLabel.append(access);

    const status = document.createElement("p");
    status.className = "share-dialog-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    const actions = document.createElement("div");
    actions.className = "share-dialog-actions";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "button button-secondary";
    cancel.textContent = "Cancel";
    cancel.addEventListener("click", () => dialog.close());
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "button button-primary";
    submit.textContent = "Grant access";
    actions.append(cancel, submit);
    form.append(recipientLabel, accessLabel, status, actions);
    dialog.append(heading, description, form);
    dialog.addEventListener("close", () => dialog.remove(), { once: true });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = recipient.value.trim();
      const numericId = /^\d+$/.test(value) ? Number(value) : null;
      if (numericId !== null && (!Number.isSafeInteger(numericId) || numericId < 1)) {
        showStatus(status, "Enter a valid registered user ID.", true);
        return;
      }
      submit.disabled = true;
      showStatus(status, "Granting read access…");
      try {
        const payload = numericId === null
          ? { user_email: value }
          : { user_id: numericId };
        await apiJson(
          `/api/documents/${encodeURIComponent(documentData.id)}/permissions`,
          { method: "POST", body: JSON.stringify(payload) },
        );
        showStatus(status, "Read access granted.");
        await refreshNotificationCount();
        form.reset();
        access.value = "read";
      } catch (error) {
        showStatus(status, errorMessage(error), true);
      } finally {
        submit.disabled = false;
      }
    });
    document.body.append(dialog);
    dialog.showModal();
    recipient.focus();
  });
  return button;
}

function fileActionMenu(documentData) {
  const wrapper = document.createElement("div");
  wrapper.className = "row-actions";
  const toggle = document.createElement("button");
  toggle.className = "table-menu";
  toggle.type = "button";
  toggle.textContent = "···";
  toggle.setAttribute("aria-label", `Actions for ${documentData.filename}`);
  toggle.setAttribute("aria-expanded", "false");
  const menu = document.createElement("div");
  menu.className = "row-menu";
  menu.hidden = true;
  menu.append(downloadButton(documentData));
  toggle.addEventListener("click", () => {
    const open = toggle.getAttribute("aria-expanded") === "true";
    toggle.setAttribute("aria-expanded", String(!open));
    menu.hidden = open;
  });
  wrapper.append(toggle, menu);
  return wrapper;
}

function documentActions(documentData) {
  const actions = document.createElement("div");
  actions.className = "document-actions";
  actions.append(shareDocumentButton(documentData), fileActionMenu(documentData));
  return actions;
}

function makeCell(content) {
  const cell = document.createElement("td");
  if (content instanceof Node) cell.append(content);
  else cell.textContent = String(content);
  return cell;
}

function createDocumentRow(documentData, ownerEmail) {
  const extension = fileExtension(documentData.filename);
  const row = document.createElement("tr");
  row.dataset.type = extension;
  row.dataset.date = documentData.created_at;
  row.dataset.search = `${documentData.title} ${documentData.filename} ${extension} ${ownerEmail}`.toLocaleLowerCase();
  row.append(
    makeCell(createFileCell(documentData)),
    makeCell(Object.assign(document.createElement("span"), {
      className: `file-type ${fileTypeClass(extension)}`,
      textContent: extension || "FILE",
    })),
    makeCell(formatFileSize(documentData.size_bytes)),
    makeCell(formatDate(documentData.created_at)),
  );
  const owner = document.createElement("span");
  owner.className = "owner-cell";
  const avatar = document.createElement("span");
  avatar.className = "mini-avatar";
  avatar.textContent = ownerEmail.slice(0, 2).toUpperCase();
  owner.append(avatar, document.createTextNode(` ${ownerEmail}`));
  row.append(makeCell(owner), makeCell(documentActions(documentData)));
  return row;
}

let ownedDocuments = [];
let currentUser = null;
let documentSearchTimer = null;
let documentSearchRequest = 0;

function applyDocumentFilters() {
  const tbody = document.querySelector("[data-document-rows]");
  const rows = tbody ? [...tbody.querySelectorAll("tr[data-type]")] : [];
  const search = document.querySelector("[data-document-search]");
  const globalSearch = document.querySelector(".dashboard-content .global-search input");
  const typeFilter = document.querySelector("[data-document-type]");
  const dateFilter = document.querySelector("[data-document-date]");
  const type = typeFilter ? typeFilter.value : "all";
  const date = dateFilter ? dateFilter.value : "all";
  const queries = [search, globalSearch]
    .filter(Boolean)
    .flatMap((input) => input.value.trim().toLocaleLowerCase().split(/\s+/))
    .filter(Boolean);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const weekAgo = new Date(today);
  weekAgo.setDate(today.getDate() - 6);
  let visible = 0;

  rows.forEach((row) => {
    const createdAt = new Date(row.dataset.date);
    const matchesDate = date === "all"
      || (date === "today" && createdAt >= today)
      || (date === "week" && createdAt >= weekAgo);
    const matches = queries.every((query) => row.dataset.search.includes(query))
      && (type === "all" || row.dataset.type === type)
      && matchesDate;
    row.hidden = !matches;
    if (matches) visible += 1;
  });
  const count = document.querySelector("[data-document-count]");
  if (count) count.textContent = `Showing ${visible} of ${rows.length} documents`;
}

async function loadOwnedDocuments() {
  const tbody = document.querySelector("[data-document-rows]");
  const summary = document.querySelector("[data-document-count]");
  const total = document.querySelector("[data-document-total]");
  if (!tbody) return;
  const requestId = ++documentSearchRequest;
  showTableState(tbody, 6, "Loading documents…");

  try {
    const params = new URLSearchParams();
    const queries = [
      document.querySelector("[data-document-search]"),
      document.querySelector(".dashboard-content .global-search input"),
    ].filter(Boolean).flatMap((input) => input.value.trim().split(/\s+/)).filter(Boolean);
    if (queries.length) params.set("q", queries.join(" "));
    const ownerFilter = document.querySelector("[data-document-owner]");
    if (ownerFilter && ownerFilter.value.trim()) params.set("owner", ownerFilter.value.trim());
    const typeFilter = document.querySelector("[data-document-type]");
    if (typeFilter && typeFilter.value !== "all") params.set("category", typeFilter.value);
    const dateFilter = document.querySelector("[data-document-date]");
    if (dateFilter && dateFilter.value !== "all") {
      const start = new Date();
      start.setHours(0, 0, 0, 0);
      if (dateFilter.value === "week") start.setDate(start.getDate() - 6);
      params.set("since", `${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, "0")}-${String(start.getDate()).padStart(2, "0")}`);
    }
    const query = params.toString();
    [ownedDocuments, currentUser] = await Promise.all([
      apiJson(`/api/documents${query ? `?${query}` : ""}`),
      loadProfile(),
    ]);
    if (requestId !== documentSearchRequest) return;
    if (total) total.textContent = String(ownedDocuments.length);
    tbody.replaceChildren();
    if (!ownedDocuments.length) {
      showTableState(
        tbody,
        6,
        query ? "No documents match these filters." : "No documents yet. Upload a file to get started.",
      );
    } else {
      ownedDocuments.forEach((item) => tbody.append(createDocumentRow(item, currentUser.email)));
    }
    if (summary) summary.textContent = `Showing ${ownedDocuments.length} matching documents`;
    applyDocumentFilters();
  } catch (error) {
    if (requestId !== documentSearchRequest) return;
    const message = errorMessage(error);
    showTableState(tbody, 6, message, true);
    showStatus(summary, message, true);
  }
}

function initializeDocumentPage() {
  const tbody = document.querySelector("[data-document-rows]");
  if (!tbody) return;
  loadOwnedDocuments();

  [
    document.querySelector("[data-document-search]"),
    document.querySelector(".dashboard-content .global-search input"),
    document.querySelector("[data-document-type]"),
    document.querySelector("[data-document-date]"),
  ].filter(Boolean).forEach((control) => {
    control.addEventListener(control instanceof HTMLInputElement ? "input" : "change", () => {
      window.clearTimeout(documentSearchTimer);
      documentSearchTimer = window.setTimeout(loadOwnedDocuments, 250);
    });
  });
  const ownerFilter = document.querySelector("[data-document-owner]");
  if (ownerFilter) {
    ownerFilter.addEventListener("input", () => {
      window.clearTimeout(documentSearchTimer);
      documentSearchTimer = window.setTimeout(loadOwnedDocuments, 250);
    });
  }

  const input = document.querySelector("[data-file-input]");
  const dropZone = document.querySelector("[data-drop-zone]");
  const selectedFile = document.querySelector("[data-selected-file]");
  const uploadButton = document.querySelector("[data-upload-submit]");
  const uploadStatus = document.querySelector("[data-upload-status]");
  if (input && dropZone && selectedFile && uploadButton) {
    const showSelection = () => {
      const file = input.files && input.files[0];
      selectedFile.textContent = file ? `${file.name} · ${formatFileSize(file.size)}` : "No file selected";
      uploadButton.disabled = !file;
      showStatus(uploadStatus, "");
    };
    input.addEventListener("change", showSelection);
    dropZone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("is-dragging"));
    dropZone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropZone.classList.remove("is-dragging");
      const files = event.dataTransfer && event.dataTransfer.files;
      if (!files || !files.length) return;
      const transfer = new DataTransfer();
      transfer.items.add(files[0]);
      input.files = transfer.files;
      showSelection();
    });
    uploadButton.addEventListener("click", async () => {
      const file = input.files && input.files[0];
      if (!file) return;
      const formData = new FormData();
      formData.append("file", file);
      uploadButton.disabled = true;
      showStatus(uploadStatus, "Uploading document…");
      try {
        await apiJson("/api/documents", { method: "POST", body: formData });
        input.value = "";
        showSelection();
        showStatus(uploadStatus, "Document uploaded successfully.");
        await loadOwnedDocuments();
      } catch (error) {
        showStatus(uploadStatus, errorMessage(error), true);
      } finally {
        uploadButton.disabled = !(input.files && input.files.length);
      }
    });
  }

  const openUpload = document.querySelector("[data-open-upload]");
  if (openUpload && input) {
    openUpload.addEventListener("click", () => {
      const panel = document.querySelector("#upload-panel");
      if (panel) panel.scrollIntoView({ behavior: "smooth", block: "center" });
      input.click();
    });
  }
}

function createSharedRow(item) {
  const row = document.createElement("tr");
  const owner = document.createElement("span");
  owner.className = "owner-cell";
  const avatar = document.createElement("span");
  avatar.className = "mini-avatar";
  avatar.textContent = `#${item.owner_id}`;
  owner.append(avatar, document.createTextNode(` Account #${item.owner_id}`));
  const permission = document.createElement("span");
  permission.className = "permission-badge permission-read";
  permission.textContent = "Read only · Viewer";
  row.append(
    makeCell(createFileCell(item)),
    makeCell(owner),
    makeCell(permission),
    makeCell(formatDate(item.created_at)),
    makeCell(downloadButton(item)),
  );
  row.dataset.search = `${item.title} ${item.filename} ${item.owner_id}`.toLocaleLowerCase();
  return row;
}

function initializeSharedPage() {
  const tbody = document.querySelector("[data-shared-rows]");
  if (!tbody) return;
  const count = document.querySelector("[data-shared-count]");
  const total = document.querySelector("[data-shared-total]");
  const search = document.querySelector("[data-shared-search]");
  const status = document.querySelector("[data-shared-status]");
  showTableState(tbody, 5, "Loading shared documents…");

  apiJson("/api/documents/shared-with-me").then(async (items) => {
    await loadProfile();
    tbody.replaceChildren();
    if (!items.length) showTableState(tbody, 5, "No documents have been shared with you.");
    else items.forEach((item) => tbody.append(createSharedRow(item)));
    if (count) count.textContent = `Showing ${items.length} shared documents`;
    if (total) total.textContent = String(items.length);
    if (search) {
      search.addEventListener("input", () => {
        const query = search.value.trim().toLocaleLowerCase();
        let visible = 0;
        tbody.querySelectorAll("tr[data-search]").forEach((row) => {
          row.hidden = !row.dataset.search.includes(query);
          if (!row.hidden) visible += 1;
        });
        if (count) count.textContent = `Showing ${visible} of ${items.length} shared documents`;
      });
    }
  }).catch((error) => {
    showTableState(tbody, 5, errorMessage(error), true);
    showStatus(count, errorMessage(error), true);
    showStatus(status, errorMessage(error), true);
  });
}

function initializePermissionsPage() {
  const tbody = document.querySelector("[data-permission-rows]");
  if (!tbody) return;
  const count = document.querySelector("[data-permission-count]");
  const total = document.querySelector("[data-permission-total]");
  const search = document.querySelector("[data-permission-search]");
  const documentSelect = document.querySelector("[data-permission-document]");
  const emailInput = document.querySelector("[data-permission-email]");
  const form = document.querySelector("[data-permission-grant]");
  const submit = document.querySelector("[data-permission-submit]");
  const status = document.querySelector("[data-permission-status]");
  let owned = [];
  let permissionRows = [];

  const renderPermissions = () => {
    const query = search ? search.value.trim().toLocaleLowerCase() : "";
    tbody.replaceChildren();
    const visible = permissionRows.filter((entry) => {
      const text = `${entry.document.title} ${entry.permission.user_email} ${entry.permission.access_level}`.toLocaleLowerCase();
      return text.includes(query);
    });
    if (!visible.length) {
      showTableState(tbody, 5, permissionRows.length ? "No permissions match your search." : "No active sharing permissions.");
    } else {
      visible.forEach(({ document: doc, permission }) => {
        const person = document.createElement("span");
        person.className = "owner-cell";
        const avatar = document.createElement("span");
        avatar.className = "mini-avatar";
        avatar.textContent = permission.user_email.slice(0, 2).toUpperCase();
        person.append(avatar, document.createTextNode(` ${permission.user_email}`));
        const badge = document.createElement("span");
        badge.className = "permission-badge permission-read";
        badge.textContent = "Read";
        const revoke = document.createElement("button");
        revoke.type = "button";
        revoke.className = "button button-secondary";
        revoke.textContent = "Revoke";
        revoke.addEventListener("click", async () => {
          revoke.disabled = true;
          showStatus(status, "Revoking document access…");
          try {
            await apiJson(
              `/api/documents/${encodeURIComponent(doc.id)}/permissions/${permission.id}`,
              { method: "DELETE" },
            );
            await refreshPermissions();
            showStatus(status, "Document access revoked.");
          } catch (error) {
            showStatus(status, errorMessage(error), true);
            revoke.disabled = false;
          }
        });
        const row = document.createElement("tr");
        row.append(
          makeCell(createFileCell(doc)),
          makeCell(person),
          makeCell(badge),
          makeCell(formatDate(permission.created_at)),
          makeCell(revoke),
        );
        tbody.append(row);
      });
    }
    if (count) count.textContent = `Showing ${visible.length} of ${permissionRows.length} active permissions`;
    if (total) total.textContent = String(permissionRows.length);
  };

  const refreshPermissions = async () => {
    permissionRows = (await Promise.all(owned.map(async (doc) => {
      const permissions = await apiJson(
        `/api/documents/${encodeURIComponent(doc.id)}/permissions`,
      );
      return permissions.map((permission) => ({ document: doc, permission }));
    }))).flat();
    renderPermissions();
  };

  const updateSubmitState = () => {
    if (submit) submit.disabled = !documentSelect.value || !emailInput.value.trim() || !emailInput.validity.valid;
  };

  showTableState(tbody, 5, "Loading permissions…");
  Promise.all([apiJson("/api/documents"), loadProfile()]).then(async ([documents]) => {
    owned = documents;
    documentSelect.replaceChildren(new Option("Choose a document", ""));
    owned.forEach((doc) => documentSelect.add(new Option(doc.title || doc.filename, doc.id)));
    await refreshPermissions();
    if (!owned.length) showStatus(status, "Upload a document before granting access.");
    updateSubmitState();
  }).catch((error) => {
    showTableState(tbody, 5, errorMessage(error), true);
    showStatus(count, errorMessage(error), true);
    showStatus(status, errorMessage(error), true);
  });

  if (search) search.addEventListener("input", renderPermissions);
  if (documentSelect) documentSelect.addEventListener("change", updateSubmitState);
  if (emailInput) emailInput.addEventListener("input", updateSubmitState);
  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!documentSelect.value || !emailInput.validity.valid) return;
      submit.disabled = true;
      showStatus(status, "Granting read access…");
      try {
        await apiJson(
          `/api/documents/${encodeURIComponent(documentSelect.value)}/permissions`,
          {
            method: "POST",
            body: JSON.stringify({ user_email: emailInput.value.trim() }),
          },
        );
        emailInput.value = "";
        await refreshPermissions();
        await refreshNotificationCount();
        showStatus(status, "Read access granted.");
      } catch (error) {
        showStatus(status, errorMessage(error), true);
      } finally {
        updateSubmitState();
      }
    });
  }
}

const AUDIT_ACTIONS = {
  user_registered: ["Registered", "action-viewed"],
  user_logged_in: ["Signed in", "action-viewed"],
  document_uploaded: ["Uploaded", "action-uploaded"],
  document_downloaded: ["Downloaded", "action-downloaded"],
  document_download_failed: ["Download failed", "action-updated"],
  document_access_granted: ["Access granted", "action-shared"],
  document_access_revoked: ["Access revoked", "action-updated"],
  document_access_denied: ["Access denied", "action-updated"],
  document_access_grant_denied: ["Share denied", "action-updated"],
  document_access_revoke_denied: ["Revoke denied", "action-updated"],
  document_permissions_read_denied: ["Permission list denied", "action-updated"],
  document_permissions_listed: ["Permissions viewed", "action-viewed"],
  document_edited: ["Edited", "action-updated"],
  document_edit_denied: ["Edit denied", "action-updated"],
  document_deleted: ["Deleted", "action-updated"],
  document_delete_denied: ["Delete denied", "action-updated"],
  document_upload_denied: ["Upload denied", "action-updated"],
  document_listed: ["Documents viewed", "action-viewed"],
  shared_documents_listed: ["Shared documents viewed", "action-viewed"],
};

function auditDescription(event) {
  const details = event.details_json;
  if (!details) return "—";
  try {
    const values = JSON.parse(details);
    return Object.entries(values).map(([key, value]) => `${key.replaceAll("_", " ")}: ${value}`).join(" · ");
  } catch (error) {
    if (error instanceof SyntaxError) return details;
    throw error;
  }
}

function createAuditRow(event, email, isAdmin = false) {
  const [label, actionClass] = AUDIT_ACTIONS[event.action] || [event.action.replaceAll("_", " "), "action-viewed"];
  const actor = document.createElement("span");
  actor.className = "owner-cell";
  const avatar = document.createElement("span");
  avatar.className = "mini-avatar";
  const actorLabel = isAdmin
    ? (event.actor_user_id ? `Account #${event.actor_user_id}` : "System")
    : email;
  avatar.textContent = actorLabel.slice(0, 2).toUpperCase();
  actor.append(avatar, document.createTextNode(` ${actorLabel}`));
  const action = document.createElement("span");
  action.className = `action-pill ${actionClass}`;
  action.textContent = label;
  const resource = event.resource_id
    ? `${event.resource_type} · ${event.resource_id}`
    : event.resource_type;
  const timestamp = document.createElement("time");
  timestamp.dateTime = event.created_at;
  timestamp.textContent = formatDate(event.created_at);
  const row = document.createElement("tr");
  row.dataset.action = event.action;
  row.dataset.date = new Date(event.created_at).toISOString().slice(0, 10);
  row.append(
    makeCell(actor),
    makeCell(action),
    makeCell(resource),
    makeCell(timestamp),
    makeCell(auditDescription(event)),
  );
  return row;
}

let auditEvents = [];

function applyAuditFilters() {
  const tbody = document.querySelector("[data-audit-rows]");
  if (!tbody) return;
  const search = document.querySelector("[data-audit-search]");
  const globalSearch = document.querySelector(".dashboard-content .global-search input");
  const action = document.querySelector("[data-audit-action]");
  const from = document.querySelector("[data-audit-from]");
  const to = document.querySelector("[data-audit-to]");
  const queries = [search, globalSearch]
    .filter(Boolean)
    .map((input) => input.value.trim().toLocaleLowerCase())
    .filter(Boolean);
  let visible = 0;
  tbody.querySelectorAll("tr[data-action]").forEach((row) => {
    const matches = queries.every((query) => row.textContent.toLocaleLowerCase().includes(query))
      && (!action || action.value === "all" || row.dataset.action === action.value)
      && (!from || !from.value || row.dataset.date >= from.value)
      && (!to || !to.value || row.dataset.date <= to.value);
    row.hidden = !matches;
    if (matches) visible += 1;
  });
  const count = document.querySelector("[data-audit-count]");
  if (count) count.textContent = `Showing ${visible} of ${auditEvents.length} activity events`;
}

function localDateToUtc(dateString, endOfDay = false) {
  if (!dateString) return "";
  const date = new Date(`${dateString}T00:00:00`);
  if (endOfDay) date.setDate(date.getDate() + 1);
  return new Date(date.getTime() - (endOfDay ? 1 : 0)).toISOString();
}

function initializeAuditPage() {
  const tbody = document.querySelector("[data-audit-rows]");
  if (!tbody) return;
  const status = document.querySelector("[data-audit-status]");
  const count = document.querySelector("[data-audit-count]");
  const errorStatus = document.querySelector("[data-audit-error] span");
  const actionFilter = document.querySelector("[data-audit-action]");
  const from = document.querySelector("[data-audit-from]");
  const to = document.querySelector("[data-audit-to]");
  const weekCount = document.querySelector("[data-audit-week-count]");
  const documentCount = document.querySelector("[data-audit-document-count]");
  showTableState(tbody, 5, "Loading audit events…");

  loadProfile().then(async (user) => {
    const isAdmin = user.role === "admin";
    const endpoint = isAdmin ? "/api/admin/audit?limit=500" : "/api/audit?limit=500";
    const events = await apiJson(endpoint);
    auditEvents = events;
    tbody.replaceChildren();
    if (!events.length) showTableState(tbody, 5, isAdmin ? "No audit events have been recorded." : "No audit events have been recorded for your account.");
    else events.forEach((event) => tbody.append(createAuditRow(event, user.email, isAdmin)));
    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    if (weekCount) weekCount.textContent = String(events.filter((event) => new Date(event.created_at).getTime() >= weekAgo).length);
    if (documentCount) {
      documentCount.textContent = String(new Set(
        events.filter((event) => event.resource_type === "document" && event.resource_id).map((event) => event.resource_id),
      ).size);
    }
    const account = document.querySelector("[data-audit-account]");
    if (account) {
      account.textContent = user.email;
      account.title = user.email;
      account.dataset.role = user.role;
    }
    if (status) status.textContent = "Live API data";
    const description = document.querySelector(".audit-panel-heading p");
    if (description) {
      description.textContent = isAdmin
        ? "Administrator view: activity events across TrustVault accounts."
        : "Showing events recorded by the API for your signed-in account.";
    }
    const scope = document.querySelector("[data-audit-user]");
    if (scope) {
      scope.replaceChildren(new Option(isAdmin ? "All accounts (Admin)" : "Signed-in user only", "all"));
      scope.disabled = true;
    }
    if (errorStatus) errorStatus.textContent = "";
    applyAuditFilters();
  }).catch((error) => {
    showTableState(tbody, 5, errorMessage(error), true);
    showStatus(count, errorMessage(error), true);
    showStatus(status, "Unable to load", true);
    showStatus(errorStatus, errorMessage(error), true);
  });

  [
    document.querySelector("[data-audit-search]"),
    document.querySelector(".dashboard-content .global-search input"),
    actionFilter,
    from,
    to,
  ].filter(Boolean).forEach((control) => {
    control.addEventListener(control instanceof HTMLInputElement && control.type === "search" ? "input" : "change", applyAuditFilters);
  });

  const clear = document.querySelector("[data-clear-audit]");
  if (clear) {
    clear.addEventListener("click", () => {
      [document.querySelector("[data-audit-search]"), from, to, document.querySelector(".dashboard-content .global-search input")]
        .filter(Boolean).forEach((control) => { control.value = ""; });
      if (actionFilter) actionFilter.value = "all";
      applyAuditFilters();
    });
  }

  const exportButton = document.querySelector("[data-audit-export]");
  if (exportButton) {
    exportButton.addEventListener("click", async () => {
      const params = new URLSearchParams({ limit: "500" });
      if (actionFilter && actionFilter.value !== "all") params.set("action", actionFilter.value);
      if (from && from.value) params.set("since", localDateToUtc(from.value));
      if (to && to.value) params.set("until", localDateToUtc(to.value, true));
      exportButton.disabled = true;
      showStatus(status, "Preparing audit export…");
      try {
        const account = document.querySelector("[data-audit-account]");
        const isAdmin = account && account.dataset.role === "admin";
        const endpoint = isAdmin ? "/api/admin/audit/export.csv" : "/api/audit/export.csv";
        const response = await apiRequest(`${endpoint}?${params}`);
        const url = URL.createObjectURL(await response.blob());
        const link = document.createElement("a");
        link.href = url;
        link.download = "trustvault-audit.csv";
        document.body.append(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        showStatus(status, "Audit export downloaded.");
      } catch (error) {
        showStatus(status, errorMessage(error), true);
      } finally {
        exportButton.disabled = false;
      }
    });
  }
}

function initializeAdminDashboard() {
  const dashboard = document.querySelector("[data-admin-dashboard]");
  const usersBody = document.querySelector("[data-admin-users]");
  const activityBody = document.querySelector("[data-admin-login-activity]");
  if (!dashboard || !usersBody || !activityBody) return;
  const status = document.querySelector("[data-admin-status]");
  const userCount = document.querySelector("[data-admin-user-count]");
  const loginCount = document.querySelector("[data-admin-login-count]");
  const usersSearch = document.querySelector("[data-admin-user-search]");
  const loginSearch = document.querySelector("[data-admin-login-search]");
  let registeredUsers = [];
  let loginActivity = [];
  showTableState(usersBody, 4, "Loading registered users…");
  showTableState(activityBody, 4, "Loading login activity…");

  const renderUsers = () => {
    const query = usersSearch ? usersSearch.value.trim().toLocaleLowerCase() : "";
    const visible = registeredUsers.filter((user) =>
      `${user.email} ${user.display_name || ""} ${user.role}`.toLocaleLowerCase().includes(query),
    );
    usersBody.replaceChildren();
    if (!visible.length) {
      showTableState(usersBody, 4, registeredUsers.length ? "No users match your search." : "No registered users yet.");
    } else {
      visible.forEach((user) => {
        const row = document.createElement("tr");
        row.append(
          makeCell(user.display_name || "User"),
          makeCell(user.email),
          makeCell(user.role === "admin" ? "Admin" : "User"),
          makeCell(formatDate(user.created_at)),
        );
        usersBody.append(row);
      });
    }
    if (userCount) userCount.textContent = `${visible.length} shown`;
  };

  const renderLoginActivity = () => {
    const query = loginSearch ? loginSearch.value.trim().toLocaleLowerCase() : "";
    const visible = loginActivity.filter((entry) =>
      `${entry.identifier || "Unknown"} ${entry.outcome} ${entry.provider || ""}`
        .toLocaleLowerCase()
        .includes(query),
    );
    activityBody.replaceChildren();
    if (!visible.length) {
      showTableState(
        activityBody,
        4,
        loginActivity.length ? "No activity matches your search." : "No login activity has been recorded.",
      );
    } else {
      visible.forEach((entry) => {
        const row = document.createElement("tr");
        const outcome = document.createElement("span");
        outcome.className = `action-pill ${entry.outcome === "success" ? "action-viewed" : "action-updated"}`;
        outcome.textContent = entry.outcome === "success"
          ? "Successful login"
          : entry.outcome === "failure"
            ? "Failed login"
            : "Signed out";
        const occurredAt = document.createElement("time");
        occurredAt.dateTime = entry.created_at;
        occurredAt.textContent = formatDate(entry.created_at);
        row.append(
          makeCell(entry.identifier || "Identifier unavailable"),
          makeCell(outcome),
          makeCell(entry.provider || "—"),
          makeCell(occurredAt),
        );
        activityBody.append(row);
      });
    }
    if (loginCount) {
      loginCount.textContent = `${loginActivity.filter((entry) => entry.outcome === "success").length} successful · ${loginActivity.filter((entry) => entry.outcome === "failure").length} failed`;
    }
  };

  loadProfile().then((user) => {
    if (user.role !== "admin") {
      window.location.replace("dashboard.html");
      return null;
    }
    return Promise.all([
      apiJson("/api/admin/users?limit=500"),
      apiJson("/api/admin/login-activity?limit=500"),
    ]);
  }).then((data) => {
    if (!data) return;
    const [users, activity] = data;
    dashboard.hidden = false;
    registeredUsers = users;
    loginActivity = activity;
    renderUsers();
    renderLoginActivity();
    if (status) status.textContent = "Live data · activity is stored in the database";
  }).catch((error) => {
    if (error instanceof AuthenticationError) {
      window.location.replace("login.html");
      return;
    }
    showTableState(usersBody, 4, errorMessage(error), true);
    showTableState(activityBody, 4, errorMessage(error), true);
    showStatus(status, errorMessage(error), true);
  });

  if (usersSearch) usersSearch.addEventListener("input", renderUsers);
  if (loginSearch) loginSearch.addEventListener("input", renderLoginActivity);
}

function createDashboardDocumentRow(item) {
  const extension = fileExtension(item.filename);
  const row = document.createElement("tr");
  const modified = new Date(item.created_at);
  const recent = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(
    Math.round((modified.getTime() - Date.now()) / (24 * 60 * 60 * 1000)),
    "day",
  );
  const type = document.createElement("span");
  type.className = `file-type ${fileTypeClass(extension)}`;
  type.textContent = extension || "FILE";
  row.append(
    makeCell(createFileCell(item)),
    makeCell(recent),
    makeCell(type),
    makeCell(documentActions(item)),
  );
  return row;
}

function initializeDashboard() {
  const root = document.querySelector("#dashboard");
  if (!root) return;
  const status = document.querySelector("[data-dashboard-status]");
  const documentRows = document.querySelector("[data-dashboard-documents]");
  const activityList = document.querySelector("[data-dashboard-activity-list]");
  const metricTotal = document.querySelector("[data-dashboard-total]");
  const metricShared = document.querySelector("[data-dashboard-shared]");
  const metricActivity = document.querySelector("[data-dashboard-activity]");
  const metricStorage = document.querySelector("[data-dashboard-storage]");

  Promise.all([
    apiJson("/api/documents"),
    apiJson("/api/documents/shared-with-me"),
    apiJson("/api/audit?limit=100"),
    loadProfile(),
  ]).then(([documents, shared, events]) => {
    if (metricTotal) metricTotal.textContent = String(documents.length);
    if (metricShared) metricShared.textContent = String(shared.length);
    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    if (metricActivity) {
      metricActivity.textContent = String(events.filter((event) => new Date(event.created_at).getTime() >= weekAgo).length);
    }
    if (metricStorage) metricStorage.textContent = formatFileSize(
      documents.reduce((total, item) => total + item.size_bytes, 0),
    );
    if (documentRows) {
      documentRows.replaceChildren();
      const recent = documents.slice(0, 5);
      if (!recent.length) showTableState(documentRows, 4, "No documents yet.");
      else recent.forEach((item) => documentRows.append(createDashboardDocumentRow(item)));
    }
    if (activityList) {
      activityList.replaceChildren();
      if (!events.length) {
        const item = document.createElement("li");
        item.textContent = "No activity has been recorded yet.";
        activityList.append(item);
      } else {
        events.slice(0, 4).forEach((event) => {
          const item = document.createElement("li");
          const avatar = document.createElement("span");
          avatar.className = "activity-avatar activity-blue";
          avatar.textContent = "TV";
          const copy = document.createElement("span");
          copy.className = "activity-copy";
          const title = document.createElement("strong");
          title.textContent = (AUDIT_ACTIONS[event.action] || [event.action.replaceAll("_", " ")])[0];
          const detail = document.createElement("small");
          detail.textContent = event.resource_type === "document" && event.resource_id
            ? `Document ${event.resource_id}`
            : event.resource_type;
          const time = document.createElement("time");
          time.textContent = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(
            Math.round((new Date(event.created_at).getTime() - Date.now()) / (60 * 60 * 1000)),
            "hour",
          );
          copy.append(title, detail);
          item.append(avatar, copy, time);
          activityList.append(item);
        });
      }
    }
    if (status) status.textContent = "Workspace data loaded";
  }).catch((error) => {
    if (status) showStatus(status, errorMessage(error), true);
    if (documentRows) showTableState(documentRows, 4, errorMessage(error), true);
    if (activityList) {
      activityList.replaceChildren();
      const item = document.createElement("li");
      item.textContent = errorMessage(error);
      item.dataset.state = "error";
      activityList.append(item);
    }
    [metricTotal, metricShared, metricActivity, metricStorage]
      .filter(Boolean).forEach((metric) => { metric.textContent = "—"; });
  });
}
