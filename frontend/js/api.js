/**
 * NETSENTRY API Client
 */
const API = {
  getToken() {
    return localStorage.getItem("netsentry_token");
  },

  setToken(token) {
    localStorage.setItem("netsentry_token", token);
  },

  clearToken() {
    localStorage.removeItem("netsentry_token");
    localStorage.removeItem("netsentry_user");
  },

  getUser() {
    try {
      return JSON.parse(localStorage.getItem("netsentry_user") || "null");
    } catch (e) {
      return null;
    }
  },

  setUser(user) {
    localStorage.setItem("netsentry_user", JSON.stringify(user));
  },

  async request(endpoint, options = {}) {
    const token = this.getToken();
    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {})
    };

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(endpoint, {
        ...options,
        headers
      });

      if (response.status === 401 && !endpoint.includes("/api/auth/login") && !endpoint.includes("/api/auth/setup-status")) {
        this.clearToken();
        window.location.href = "/login.html";
        return null;
      }

      if (response.status === 204) {
        return null;
      }

      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.detail || "API Request Failed");
        }
        return data;
      } else {
        if (!response.ok) {
          throw new Error("HTTP Error " + response.status);
        }
        return response;
      }
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  },

  // Auth
  checkSetupStatus() {
    return this.request("/api/auth/setup-status");
  },
  setupInitialAdmin(data) {
    return this.request("/api/auth/setup", { method: "POST", body: JSON.stringify(data) });
  },
  login(username, password) {
    return this.request("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
  },
  logout() {
    return this.request("/api/auth/logout", { method: "POST" });
  },
  getMe() {
    return this.request("/api/auth/me");
  },
  changePassword(current_password, new_password) {
    return this.request("/api/auth/change-password", { method: "POST", body: JSON.stringify({ current_password, new_password }) });
  },

  // Devices
  getDevices(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/api/devices?${query}`);
  },
  getDashboardSummary() {
    return this.request("/api/devices/summary");
  },
  getDeviceDetail(id) {
    return this.request(`/api/devices/${id}`);
  },
  setDeviceTrust(id, trusted) {
    return this.request(`/api/devices/${id}/trust?trusted=${trusted}`, { method: "POST" });
  },
  updateDeviceLabel(id, custom_label) {
    return this.request(`/api/devices/${id}/label`, { method: "POST", body: JSON.stringify({ custom_label }) });
  },
  revokeClient(id) {
    return this.request(`/api/devices/${id}/revoke-client`, { method: "POST" });
  },

  // Network
  getNetworkStatus() {
    return this.request("/api/network/status");
  },
  triggerScan() {
    return this.request("/api/network/scan", { method: "POST" });
  },
  startMonitoring() {
    return this.request("/api/network/monitor/start", { method: "POST" });
  },
  stopMonitoring() {
    return this.request("/api/network/monitor/stop", { method: "POST" });
  },
  updateSubnet(subnet) {
    return this.request("/api/network/subnet", { method: "POST", body: JSON.stringify({ subnet }) });
  },
  toggleDemoMode(enabled) {
    return this.request("/api/network/demo-mode", { method: "POST", body: JSON.stringify({ enabled }) });
  },

  // Camera
  requestCamera(deviceId, purpose = "Authorized network monitoring/research", durationMinutes = 10) {
    return this.request(`/api/camera/request/${deviceId}`, {
      method: "POST",
      body: JSON.stringify({ purpose, duration_minutes: durationMinutes })
    });
  },
  terminateCameraSession(sessionUuid) {
    return this.request(`/api/camera/${sessionUuid}/terminate`, { method: "POST" });
  },
  getCameraSessions() {
    return this.request("/api/camera/sessions");
  },
  getCameraSession(uuid) {
    return this.request(`/api/camera/sessions/${uuid}`);
  },

  // Client Enrollment
  generateRegistrationCode() {
    return this.request("/api/client/generate-code", { method: "POST" });
  },

  // Alerts
  getAlerts(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/api/alerts?${query}`);
  },
  getUnreadAlertCount() {
    return this.request("/api/alerts/unread-count");
  },
  markAlertRead(id) {
    return this.request(`/api/alerts/${id}/read`, { method: "POST" });
  },
  markAllAlertsRead() {
    return this.request("/api/alerts/read-all", { method: "POST" });
  },
  clearAlerts() {
    return this.request("/api/alerts", { method: "DELETE" });
  },

  // Audit
  getAuditLogs(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/api/audit?${query}`);
  }
};
