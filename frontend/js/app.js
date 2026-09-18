/**
 * NETSENTRY Main Application Controller & Real-Time WebSocket Listener
 */

const App = {
  ws: null,
  wsReconnectAttempts: 0,

  init(options = {}) {
    this.checkAuth(options.requireAuth !== false);
    this.renderSidebarActive();
    this.initWebSocket();
    this.updateAlertBadge();
  },

  checkAuth(required = true) {
    const token = API.getToken();
    const isLoginPage = window.location.pathname.includes("login.html");

    if (required && !token && !isLoginPage) {
      window.location.href = "/login.html";
      return false;
    }

    if (token) {
      const user = API.getUser();
      const adminNameEl = document.getElementById("admin-display-name");
      if (adminNameEl && user) {
        adminNameEl.textContent = user.username;
      }
    }
    return true;
  },

  renderSidebarActive() {
    const currentPath = window.location.pathname;
    const links = document.querySelectorAll(".sidebar-nav .nav-link");
    links.forEach(link => {
      const href = link.getAttribute("href");
      if (href === currentPath || (currentPath === "/" && href.includes("dashboard.html")) || (currentPath.includes(href) && href !== "/")) {
        link.classList.add("active");
      } else {
        link.classList.remove("active");
      }
    });
  },

  initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const token = API.getToken();
    const tokenParam = token ? `?token=${encodeURIComponent(token)}` : "";
    const wsUrl = `${protocol}//${window.location.host}/ws/dashboard${tokenParam}`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log("[WS] Connected to NETSENTRY Dashboard Hub");
        this.wsReconnectAttempts = 0;
        this.updateHeaderPill(true);
      };

      this.ws.onmessage = (event) => {
        try {
          const sysEvent = JSON.parse(event.data);
          this.handleSystemEvent(sysEvent);
        } catch (e) {
          console.debug("WS raw message:", event.data);
        }
      };

      this.ws.onclose = () => {
        this.updateHeaderPill(false);
        const delay = Math.min(1000 * Math.pow(1.5, this.wsReconnectAttempts), 10000);
        this.wsReconnectAttempts++;
        setTimeout(() => this.initWebSocket(), delay);
      };

      this.ws.onerror = (err) => {
        console.debug("[WS] Error:", err);
      };
    } catch (e) {
      console.warn("Could not initiate WebSocket:", e);
    }
  },

  handleSystemEvent(event) {
    console.log("[EVENT]", event.event_type, event);

    // Trigger toast for key notifications
    if (event.event_type === "DEVICE_DISCOVERED") {
      this.toast(`New device discovered: ${event.data.ip_address} (${event.data.vendor || 'Unknown'})`, "info");
    } else if (event.event_type === "CAMERA_APPROVED") {
      this.toast("Camera permission GRANTED by remote user.", "success");
    } else if (event.event_type === "CAMERA_DENIED") {
      this.toast("Camera permission DENIED by user.", "error");
    } else if (event.event_type === "CAMERA_STOPPED") {
      this.toast(`Camera session stopped (${event.data.reason || 'Normal'})`, "info");
    } else if (event.event_type === "SCAN_COMPLETED") {
      this.toast(`Network scan complete: ${event.data.devices_found} devices found.`, "success");
    }

    // Refresh alert badge
    this.updateAlertBadge();

    // Notify active page handler if registered
    if (window.onSystemEvent) {
      window.onSystemEvent(event);
    }
  },

  updateHeaderPill(connected) {
    const dot = document.getElementById("header-pulse-dot");
    const statusText = document.getElementById("header-status-text");
    if (dot && statusText) {
      if (connected) {
        dot.className = "pulse-dot";
        statusText.textContent = "Live Network Active";
      } else {
        dot.className = "pulse-dot offline";
        statusText.textContent = "Reconnecting...";
      }
    }
  },

  async updateAlertBadge() {
    try {
      const data = await API.getUnreadAlertCount();
      const badge = document.getElementById("sidebar-alert-badge");
      if (badge) {
        if (data && data.unread_count > 0) {
          badge.textContent = data.unread_count;
          badge.style.display = "inline-block";
        } else {
          badge.style.display = "none";
        }
      }
    } catch (e) {}
  },

  toast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "toast-container";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span>${message}</span>
      <span style="cursor:pointer;margin-left:12px;opacity:0.6;" onclick="this.parentElement.remove()">✕</span>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      if (toast.parentElement) toast.remove();
    }, 4000);
  },

  async logout() {
    try {
      await API.logout();
    } catch (e) {}
    API.clearToken();
    window.location.href = "/login.html";
  }
};
