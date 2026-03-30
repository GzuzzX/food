/**
 * HappyFood — Frontend API Client (v3 - FIXED)
 */

async function _api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const msg = await res.text().catch(() => res.statusText);
    console.error(`❌ API Error [${res.status}]:`, path, msg);
    throw new Error(msg || `HTTP ${res.status}`);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("json") ? res.json() : res.text();
}

const DB = {
  KEYS: {
    SESSION:        "hf_session",
    SELECTED_TABLE: "hf_selected_table",
    CURRENT_ORDER:  "hf_current_order",
  },

  get(key) { 
    try { 
      const val = localStorage.getItem(key);
      console.log(`📖 GET [${key}]:`, val ? '✅' : '❌');
      return JSON.parse(val); 
    } catch { 
      return null; 
    } 
  },
  
  set(key, value) { 
    localStorage.setItem(key, JSON.stringify(value));
    console.log(`💾 SET [${key}]:`, value ? '✅' : '❌');
  },

  getSession() { 
    try { 
      return JSON.parse(sessionStorage.getItem(this.KEYS.SESSION)); 
    } catch { 
      return null; 
    } 
  },
  
  setSession(data) { 
    sessionStorage.setItem(this.KEYS.SESSION, JSON.stringify(data)); 
    console.log(`👤 Session set:`, data.role);
  },
  
  clearSession() { 
    sessionStorage.removeItem(this.KEYS.SESSION); 
    localStorage.clear(); 
    console.log("🔓 Session cleared");
  },

  requireLogin(role = null) {
    const s = this.getSession();
    if (!s) { window.location.href = "/login"; return false; }
    if (role && s.role !== role && s.role !== "admin") {
      window.location.href = "/login"; return false;
    }
    return true;
  },

  // ── Auth ─────────────────────────────────────────────────
  async login(username, password) {
    return _api("/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  },

  async addUser({ username, password, cookId }) {
    return _api("/register", {
      method: "POST",
      body: JSON.stringify({ username, password, cook_id: cookId }),
    });
  },

  // ── Invite Codes ─────────────────────────────────────────
  async createInvite(cook_id, name) {
    return _api("/invite", {
      method: "POST",
      body: JSON.stringify({ cook_id, name }),
    });
  },

  async getInvites() {
    return _api("/invite");
  },

  async cancelInvite(cook_id) {
    return _api(`/invite/${cook_id}`, { method: "DELETE" });
  },

  async verifyInvite(cook_id) {
    return _api(`/invite/verify/${encodeURIComponent(cook_id)}`);
  },

  // ── Users ────────────────────────────────────────────────
  async getUsers() {
    return _api("/users");
  },

  async deleteUser(id) {
    return _api(`/users/${id}`, { method: "DELETE" });
  },

  // ── Menu ─────────────────────────────────────────────────
  async getMenu() {
    return _api("/menu/all");
  },

  async addMenuItem(item) {
    const payload = { ...item };
    if (payload.nameTh !== undefined) {
      payload.name_th = payload.nameTh;
      delete payload.nameTh;
    }
    return _api("/menu", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async updateMenuItem(id, updates) {
    const payload = { ...updates };
    if (payload.nameTh !== undefined) {
      payload.name_th = payload.nameTh;
      delete payload.nameTh;
    }
    return _api(`/menu/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    });
  },

  async deleteMenuItem(id) {
    return _api(`/menu/${id}`, { method: "DELETE" });
  },

  // ── Tables ───────────────────────────────────────────────
  async getTables() {
    console.log("📋 Fetching tables...");
    return _api("/tables");
  },

  async setTableStatus(tableId, status, orderId = null) {
    return _api(`/tables/${tableId}`, {
      method: "PATCH",
      body: JSON.stringify({ status, order_id: orderId }),
    });
  },

  // ── Orders ───────────────────────────────────────────────
  async getOrders() {
    return _api("/orders");
  },

  async addOrder({ tableId, items, total }) {
    const order = await _api("/orders", {
      method: "POST",
      body: JSON.stringify({ tableId, items, total }),
    });
    this.set(this.KEYS.CURRENT_ORDER, order);
    return order;
  },

  async updateOrderStatus(orderId, status) {
    return _api(`/orders/${orderId}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    });
  },

  async markOrderPaid(orderId, paymentMethod = "cash") {
    return _api(`/orders/${orderId}/pay`, {
      method: "PATCH",
      body: JSON.stringify({ payment_method: paymentMethod }),
    });
  },

  async cancelOrder(orderId) {
    return _api(`/orders/${orderId}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason: "Customer cancelled" }),
    });
  },

  async getOrderReceipt(orderId) {
    return _api(`/orders/${orderId}/receipt`);
  },

  getCurrentOrder() {
    return this.get(this.KEYS.CURRENT_ORDER);
  },

  // ── Reviews ──────────────────────────────────────────────
  async getReviews() {
    return _api("/reviews");
  },

  async addReview({ orderId, tableId, rating, comment, sessionId }) {
    return _api("/reviews", {
      method: "POST",
      body: JSON.stringify({ orderId, tableId, rating, comment, sessionId }),
    });
  },

  async getCustomerHistory(sessionIds) {
    if (!sessionIds || !sessionIds.length) return [];
    return _api(`/customer-history?sessionIds=${sessionIds.join(',')}`);
  },

  // ── Sales ────────────────────────────────────────────────
  async getSales() {
    return _api("/sales");
  },

  async getTodaySales() {
    return _api("/sales/today");
  },

  async getCustomerPayments(sessionIds) {
    if (!sessionIds || !sessionIds.length) return [];
    const params = new URLSearchParams({ sessions: sessionIds.join(',') });
    return _api(`/customer-payments?${params}`);
  },

  async getPaymentMethods(period = 'day') {
    try {
      return _api(`/analytics/payment-methods?period=${period}`);
    } catch (err) {
      console.error("Payment analytics error:", err);
      return [];
    }
  },

  async getSessionCount(period = 'day') {
    try {
      const res = await _api(`/sessions/count?period=${period}`);
      return res.count || 0;
    } catch (err) {
      return 0;
    }
  },
};