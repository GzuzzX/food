const express = require("express");
const argon2  = require("@node-rs/argon2");
const path    = require("path");
const pool    = require("./db");
const crypto  = require("crypto");
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
//  📚 SWAGGER CONFIGURATION
// ============================================================

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'HappyFood API 🍽️',
      version: '1.0.0',
      description: 'ระบบสั่งอาหารของร้านอาหาร - Restaurant Food Ordering System API',
      contact: {
        name: 'HappyFood Support',
        email: 'support@happyfood.com',
      },
    },
    servers: [
      {
        url: `http://localhost:${process.env.PORT || 3000}`,
        description: 'Development Server',
      },
    ],
    components: {
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'User ID' },
            username: { type: 'string', description: 'ชื่อผู้ใช้งาน' },
            name: { type: 'string', description: 'ชื่อเต็ม' },
            role: { type: 'string', enum: ['admin', 'chef', 'customer'], description: 'บทบาท' },
            cook_id: { type: 'string', description: 'รหัสเชฟ' },
          },
        },
        MenuItem: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            name_th: { type: 'string' },
            price: { type: 'number' },
            category: { type: 'string' },
            img: { type: 'string' },
            available: { type: 'integer' },
            toppings: { type: 'array', items: { type: 'string' } },
          },
        },
        Order: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            tableId: { type: 'string' },
            sessionId: { type: 'string' },
            items: { type: 'array' },
            total: { type: 'number' },
            status: { type: 'string' },
            paid: { type: 'integer' },
          },
        },
      },
    },
  },
  apis: ['./app.js'],
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ============================================================
//  🔍 TEST ENDPOINTS
// ============================================================

/**
 * @swagger
 * /test-db:
 *   get:
 *     summary: ทดสอบการเชื่อมต่อ Database
 *     tags: [🧪 Testing]
 *     responses:
 *       200:
 *         description: เชื่อมต่อสำเร็จ
 */
app.get("/test-db", async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1+1 AS result");
    res.send(`✅ เชื่อมต่อ Database สำเร็จ! result = ${rows[0].result}`);
  } catch (err) {
    console.error("❌ DB Test Error:", err);
    res.status(500).send(`❌ เชื่อมต่อไม่ได้: ${err.message}`);
  }
});

/**
 * @swagger
 * /password/{raw}:
 *   get:
 *     summary: แฮช password (สำหรับทดสอบ)
 *     tags: [🧪 Testing]
 *     parameters:
 *       - in: path
 *         name: raw
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Password ที่แฮชแล้ว
 */
app.get("/password/:raw", (req, res) => {
  try {
    const hash = argon2.hashSync(req.params.raw);
    res.send(hash);
  } catch (err) {
    res.status(500).send(`❌ Hash error: ${err.message}`);
  }
});

// ============================================================
//  🔑  AUTH (PUBLIC)
// ============================================================

const inviteCodes = {};

/**
 * @swagger
 * /login:
 *   post:
 *     summary: เข้าสู่ระบบ (ทั้ง Admin, Chef, Customer)
 *     tags: [🔑 Public Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: admin
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       200:
 *         description: เข้าสู่ระบบสำเร็จ
 *       401:
 *         description: Username หรือ password ผิด
 */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [results] = await pool.query(
      "SELECT id, password, full_name AS name, role, cook_id FROM users WHERE username = ? AND is_active = TRUE",
      [username]
    );
    if (results.length !== 1) return res.status(401).send("Wrong username or password");
    const same = argon2.verifySync(results[0].password, password);
    if (!same) return res.status(401).send("Wrong username or password");
    const { id, name, role, cook_id } = results[0];
    res.json({ id, name, role, cook_id });
  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /register:
 *   post:
 *     summary: ลงทะเบียนผู้ใช้ใหม่ (Chef)
 *     tags: [🔑 Public Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               cook_id:
 *                 type: string
 *     responses:
 *       200:
 *         description: ลงทะเบียนสำเร็จ
 */
app.post("/register", async (req, res) => {
  const { username, password, cook_id } = req.body;
  if (!username || !password || !cook_id)
    return res.status(400).send("กรุณากรอกข้อมูลให้ครบ");

  const code = inviteCodes[cook_id];
  if (!code) return res.status(403).send("ไม่พบ Cook ID นี้ กรุณาติดต่อ Admin");
  if (code.usedBy) return res.status(410).send("Cook ID นี้ถูกใช้สมัครแล้ว");

  try {
    const [rows] = await pool.query("SELECT id FROM users WHERE username = ?", [username]);
    if (rows.length > 0) return res.status(409).send("Username นี้มีผู้ใช้งานแล้ว");
    const hashed = argon2.hashSync(password);
    await pool.query(
      "INSERT INTO users (id, username, password, full_name, role, cook_id) VALUES (?,?,?,?,'chef',?)",
      [cook_id, username, hashed, code.name, cook_id]
    );
    inviteCodes[cook_id].usedBy = username;
    delete inviteCodes[cook_id];
    res.send("ลงทะเบียนสำเร็จ");
  } catch (err) {
    console.error("❌ Register Error:", err);
    res.status(500).send("Database server error");
  }
});

// ============================================================
//  👨‍💼 ADMIN ENDPOINTS
// ============================================================

/**
 * @swagger
 * /admin/invite:
 *   post:
 *     summary: สร้างรหัสเชิญสำหรับเชฟ
 *     tags: [👨‍💼 Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               cook_id:
 *                 type: string
 *                 example: CHF-001
 *               name:
 *                 type: string
 *                 example: Chef John
 *     responses:
 *       200:
 *         description: สร้างสำเร็จ
 */
app.post("/admin/invite", async (req, res) => {
  const { cook_id, name } = req.body;
  if (!cook_id || !name) return res.status(400).send("กรุณาระบุ Cook ID และชื่อเชฟ");
  try {
    const [existing] = await pool.query("SELECT id FROM users WHERE id = ?", [cook_id]);
    if (existing.length > 0) return res.status(409).send("Cook ID นี้มีในระบบแล้ว");
    if (inviteCodes[cook_id]) return res.status(409).send("Cook ID นี้ถูกสร้างรหัสเชิญแล้ว รอเชฟสมัครอยู่");
    inviteCodes[cook_id] = { name, usedBy: null, createdAt: new Date().toISOString() };
    res.json({ cook_id, name, message: "สร้างรหัสเชิญสำเร็จ" });
  } catch (err) {
    console.error("❌ Invite Error:", err);
    res.status(500).send("Server error");
  }
});

/**
 * @swagger
 * /admin/invite:
 *   get:
 *     summary: ดึงรหัสเชิญทั้งหมด
 *     tags: [👨‍💼 Admin]
 *     responses:
 *       200:
 *         description: รายชื่อรหัสเชิญ
 */
app.get("/admin/invite", (_req, res) => {
  const list = Object.entries(inviteCodes).map(([cook_id, v]) => ({ cook_id, ...v }));
  res.json(list);
});

/**
 * @swagger
 * /admin/invite/{cook_id}:
 *   delete:
 *     summary: ยกเลิกรหัสเชิญ
 *     tags: [👨‍💼 Admin]
 *     parameters:
 *       - in: path
 *         name: cook_id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: ยกเลิกสำเร็จ
 */
app.delete("/admin/invite/:cook_id", (req, res) => {
  const { cook_id } = req.params;
  if (!inviteCodes[cook_id]) return res.status(404).send("ไม่พบรหัสเชิญนี้");
  delete inviteCodes[cook_id];
  res.send("ยกเลิกรหัสเชิญแล้ว");
});

/**
 * @swagger
 * /admin/users:
 *   get:
 *     summary: ดึงรายชื่อผู้ใช้งานทั้งหมด
 *     tags: [👨‍💼 Admin]
 *     responses:
 *       200:
 *         description: รายชื่อผู้ใช้งาน
 */
app.get("/admin/users", async (_req, res) => {
  try {
    const [results] = await pool.query(
      "SELECT id, username, full_name AS name, role, cook_id, is_active, created_at FROM users ORDER BY created_at"
    );
    res.json(results);
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /admin/users/{id}:
 *   delete:
 *     summary: ลบผู้ใช้งาน
 *     tags: [👨‍💼 Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: ลบสำเร็จ
 */
app.delete("/admin/users/:id", async (req, res) => {
  try {
    const [result] = await pool.query(
      "UPDATE users SET is_active = FALSE WHERE id = ? AND role != 'admin'",
      [req.params.id]
    );
    if (result.affectedRows !== 1) return res.status(400).send("Cannot delete or not found");
    res.send("Delete successfully");
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /admin/users/{id}/change-password:
 *   patch:
 *     summary: เปลี่ยน Password ผู้ใช้งาน
 *     tags: [👨‍💼 Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               new_password:
 *                 type: string
 *     responses:
 *       200:
 *         description: เปลี่ยนสำเร็จ
 */
app.patch("/admin/users/:id/change-password", async (req, res) => {
  const { new_password } = req.body;
  if (!new_password) return res.status(400).send("กรุณาระบุ password ใหม่");
  
  try {
    const hashed = argon2.hashSync(new_password);
    await pool.query(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashed, req.params.id]
    );
    res.send("เปลี่ยน Password สำเร็จ");
  } catch (err) {
    res.status(500).send("Database error");
  }
});

/**
 * @swagger
 * /admin/tables:
 *   get:
 *     summary: ดึงข้อมูลโต๊ะทั้งหมด
 *     tags: [👨‍💼 Admin]
 *     responses:
 *       200:
 *         description: ข้อมูลโต๊ะ
 */
app.get("/admin/tables", async (_req, res) => {
  try {
    const [results] = await pool.query(
      "SELECT table_id AS id, status, current_order_id AS order_id, capacity, updated_at FROM restaurant_tables ORDER BY table_id"
    );
    const tables = {};
    results.forEach(t => { 
      tables[t.id] = { 
        status: t.status || 'vacant', 
        order_id: t.order_id || null,
        capacity: t.capacity || 4,
        updated_at: t.updated_at
      }; 
    });
    res.json(tables);
  } catch (err) {
    res.status(500).json({ error: "Database server error" });
  }
});

/**
 * @swagger
 * /admin/tables:
 *   post:
 *     summary: เพิ่มโต๊ะใหม่
 *     tags: [👨‍💼 Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               table_id:
 *                 type: string
 *               table_name:
 *                 type: string
 *               capacity:
 *                 type: integer
 *     responses:
 *       200:
 *         description: เพิ่มสำเร็จ
 */
app.post("/admin/tables", async (req, res) => {
  const { table_id, table_name, capacity } = req.body;
  if (!table_id) return res.status(400).send("Table ID required");

  try {
    await pool.query(
      "INSERT INTO restaurant_tables (table_id, table_name, capacity) VALUES (?, ?, ?)",
      [table_id, table_name || `Table ${table_id}`, capacity || 4]
    );
    res.json({ success: true, table_id });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).send("Table already exists");
    }
    res.status(500).send("Server error");
  }
});

/**
 * @swagger
 * /admin/sales:
 *   get:
 *     summary: ดึงข้อมูลการขายทั้งหมด
 *     tags: [👨‍💼 Admin]
 *     responses:
 *       200:
 *         description: ข้อมูลการขาย
 */
app.get("/admin/sales", async (_req, res) => {
  try {
    const [results] = await pool.query("SELECT * FROM sales ORDER BY created_at DESC");
    results.forEach(s => { s.tableId = s.table_id; s.orderId = s.order_id; s.createdAt = s.created_at; });
    res.json(results);
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /admin/sales/today:
 *   get:
 *     summary: ดึงข้อมูลการขายประจำวัน
 *     tags: [👨‍💼 Admin]
 *     responses:
 *       200:
 *         description: ข้อมูลการขายวันนี้
 */
app.get("/admin/sales/today", async (_req, res) => {
  try {
    const [results] = await pool.query(
      "SELECT * FROM sales WHERE DATE(created_at) = CURDATE() ORDER BY created_at DESC"
    );
    results.forEach(s => { s.tableId = s.table_id; s.orderId = s.order_id; s.createdAt = s.created_at; });
    res.json(results);
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /admin/analytics/payment-methods:
 *   get:
 *     summary: วิเคราะห์วิธีการชำระเงิน
 *     tags: [👨‍💼 Admin]
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [day, week, month]
 *     responses:
 *       200:
 *         description: ข้อมูลการวิเคราะห์
 */
app.get("/admin/analytics/payment-methods", async (req, res) => {
  const period = req.query.period || 'day';
  let daysAgo = 1;
  if (period === 'week') daysAgo = 7;
  if (period === 'month') daysAgo = 30;

  try {
    const [results] = await pool.query(`
      SELECT 
        COALESCE(payment_method, 'unknown') as payment_method,
        COUNT(*) AS count,
        SUM(total) AS total,
        AVG(total) AS avg
      FROM sales
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
      GROUP BY payment_method
      ORDER BY total DESC
    `, [daysAgo]);
    
    res.json(results || []);
  } catch (err) {
    res.status(500).json({ error: "Server Error" });
  }
});

/**
 * @swagger
 * /admin/sessions/count:
 *   get:
 *     summary: นับจำนวนเซสชั่น
 *     tags: [👨‍💼 Admin]
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 */
app.get("/admin/sessions/count", async (req, res) => {
  const period = req.query.period || 'day';
  let daysAgo = 1;
  if (period === 'week') daysAgo = 7;
  if (period === 'month') daysAgo = 30;
  
  try {
    const [results] = await pool.query(
      `SELECT COUNT(DISTINCT session_id) AS count FROM customer_sessions 
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [daysAgo]
    );
    res.json({ count: results[0]?.count || 0 });
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

// ============================================================
//  👨‍🍳 CHEF ENDPOINTS
// ============================================================

/**
 * @swagger
 * /chef/orders:
 *   get:
 *     summary: ดึงคำสั่งซื้อทั้งหมด (สำหรับเชฟ)
 *     tags: [👨‍🍳 Chef]
 *     responses:
 *       200:
 *         description: รายชื่อคำสั่งซื้อ
 */
app.get("/chef/orders", async (_req, res) => {
  try {
    const result = await fetchOrdersWithItems();
    res.json(result);
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /chef/orders/active:
 *   get:
 *     summary: ดึงคำสั่งซื้อที่ยังอยู่ระหว่างดำเนินการ
 *     tags: [👨‍🍳 Chef]
 *     responses:
 *       200:
 *         description: คำสั่งซื้อที่ยังเปิดอยู่
 */
app.get("/chef/orders/active", async (_req, res) => {
  try {
    const result = await fetchOrdersWithItems(
      "WHERE o.is_paid = FALSE AND o.status NOT IN ('paid','cancelled')"
    );
    res.json(result);
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /chef/orders/{id}/status:
 *   patch:
 *     summary: อัปเดตสถานะคำสั่ง
 *     tags: [👨‍🍳 Chef]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *                 example: cooking
 *     responses:
 *       200:
 *         description: อัปเดตสำเร็จ
 */
app.patch("/chef/orders/:id/status", async (req, res) => {
  const { status } = req.body;
  try {
    const [result] = await pool.query(
      "UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?",
      [status, req.params.id]
    );
    if (result.affectedRows !== 1) return res.status(404).send("Order not found");
    res.send("Status updated");
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

// ============================================================
//  👤 CUSTOMER ENDPOINTS
// ============================================================

/**
 * @swagger
 * /customer/menu:
 *   get:
 *     summary: ดึงรายการอาหารที่พร้อมจำหน่าย
 *     tags: [👤 Customer]
 *     responses:
 *       200:
 *         description: รายการอ���หาร
 */
app.get("/customer/menu", async (_req, res) => {
  try {
    const [results] = await pool.query(MENU_SELECT + " AND mi.is_available = TRUE" + MENU_GROUP);
    res.json(results.map(m => formatMenuItem({ ...m, toppings: parseToppings(m.toppings_raw) })));
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /customer/tables:
 *   patch:
 *     summary: อัปเดตสถานะโต๊ะ (ลูกค้า)
 *     tags: [👤 Customer]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *               order_id:
 *                 type: string
 *     responses:
 *       200:
 *         description: อัปเดตสำเร็จ
 */
app.patch("/customer/tables/:id", async (req, res) => {
  const { status, order_id } = req.body;
  try {
    const [result] = await pool.query(
      "UPDATE restaurant_tables SET status = ?, current_order_id = ?, updated_at = NOW() WHERE table_id = ?",
      [status, order_id || null, req.params.id]
    );
    if (result.affectedRows !== 1) return res.status(404).send("Table not found");
    res.send("Table updated");
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /customer/start-session:
 *   post:
 *     summary: เริ่มเซสชั่นใหม่
 *     tags: [👤 Customer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               table_id:
 *                 type: string
 *     responses:
 *       200:
 *         description: เริ่มสำเร็จ
 */
app.post("/customer/start-session", async (req, res) => {
  const { table_id } = req.body;
  if (!table_id) return res.status(400).send("Table ID is required");

  const sessionId = crypto.randomUUID();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query(
      "UPDATE customer_sessions SET is_active = 0, ended_at = NOW() WHERE table_id = ? AND is_active = 1",
      [table_id]
    );
    await conn.query(
      "INSERT INTO customer_sessions (session_id, table_id, is_active) VALUES (?, ?, 1)",
      [sessionId, table_id]
    );
    await conn.commit();
    res.json({ sessionId });
  } catch (err) {
    await conn.rollback();
    res.status(500).send("Server Error");
  } finally {
    conn.release();
  }
});

/**
 * @swagger
 * /customer/end-session:
 *   post:
 *     summary: จบเซสชั่น
 *     tags: [👤 Customer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sessionId:
 *                 type: string
 *     responses:
 *       200:
 *         description: จบเซสชั่นสำเร็จ
 */
app.post("/customer/end-session", async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).send("Session ID required");
  try {
    await pool.query(
      "UPDATE customer_sessions SET is_active = 0, ended_at = NOW() WHERE session_id = ?",
      [sessionId]
    );
    res.send("Session ended");
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

/**
 * @swagger
 * /customer/orders:
 *   post:
 *     summary: สร้างคำสั่งซื้อใหม่
 *     tags: [👤 Customer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               tableId:
 *                 type: string
 *               sessionId:
 *                 type: string
 *               items:
 *                 type: array
 *               total:
 *                 type: number
 *     responses:
 *       200:
 *         description: สร้างคำสั่งสำเร็จ
 */
app.post("/customer/orders", async (req, res) => {
  const { tableId, items, total, sessionId } = req.body;
  
  if (!tableId || !items || !Array.isArray(items) || items.length === 0 || !total) {
    return res.status(400).json({ error: "ข้อมูลไม่ครบ กรุณาเลือกอาหารอย่างน้อย 1 รายการ" });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const subtotal = parseFloat(total);
    const vatRate = 0.07;
    const vatAmount = Math.round(subtotal * vatRate * 100) / 100;
    const grandTotal = subtotal + vatAmount;
    const orderId = `ORD-${Date.now()}`;

    await conn.query(
      "INSERT INTO orders (id, table_id, session_id, subtotal, vat_rate, vat_amount, total) VALUES (?,?,?,?,?,?,?)",
      [orderId, tableId, sessionId || null, subtotal, vatRate * 100, vatAmount, grandTotal]
    );

    for (const item of items) {
      const extraPrice = item.toppings.reduce((sum, top) => {
        const match = String(top).match(/\(\s*\+\s*([\d.]+)\s*\)/);
        return sum + (match ? parseFloat(match[1]) : 0);
      }, 0);
      
      const lineTotal = (item.price + (extraPrice / item.qty)) * item.qty;

      const [oi] = await conn.query(
        "INSERT INTO order_items (order_id, menu_id, menu_name_th, unit_price, qty, extra_price, line_total, special_note) VALUES (?,?,?,?,?,?,?,?)",
        [orderId, item.menuId, item.name, item.price, item.qty, extraPrice, lineTotal, item.note || null]
      );
      
      const oiId = oi.insertId;
      for (const top of (item.toppings || [])) {
        const match = String(top).match(/\(\s*\+\s*([\d.]+)\s*\)/);
        const extra = match ? parseFloat(match[1]) : 0;
        await conn.query(
          "INSERT INTO order_item_toppings (order_item_id, topping_name, extra_price) VALUES (?,?,?)",
          [oiId, top.replace(/\s*\(\s*\+\s*[\d.]+\s*\)/, "").trim(), extra]
        );
      }
    }

    await conn.query(
      "UPDATE restaurant_tables SET status = 'occupied', current_order_id = ?, updated_at = NOW() WHERE table_id = ?",
      [orderId, tableId]
    );

    await conn.commit();
    res.json({ 
      id: orderId, 
      tableId, 
      items, 
      subtotal,
      vat_amount: vatAmount,
      total: grandTotal, 
      status: "pending", 
      paid: 0 
    });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: "Database server error" });
  } finally {
    conn.release();
  }
});

/**
 * @swagger
 * /customer/orders/{id}/pay:
 *   patch:
 *     summary: ชำระเงินสำหรับคำสั่ง
 *     tags: [👤 Customer]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               payment_method:
 *                 type: string
 *     responses:
 *       200:
 *         description: ชำระเงินสำเร็จ
 */
app.patch("/customer/orders/:id/pay", async (req, res) => {
  const { payment_method = "cash" } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query("CALL sp_pay_order(?, ?)", [req.params.id, payment_method]);
    const [rows] = await conn.query("SELECT table_id FROM orders WHERE id = ?", [req.params.id]);
    if (rows.length > 0) {
      await conn.query(
        "UPDATE restaurant_tables SET status = 'cleaning', current_order_id = NULL, updated_at = NOW() WHERE table_id = ?",
        [rows[0].table_id]
      );
    }
    await conn.commit();
    res.send("Paid successfully");
  } catch (err) {
    await conn.rollback();
    res.status(500).send("Database server error");
  } finally {
    conn.release();
  }
});

/**
 * @swagger
 * /customer/orders/{id}/cancel:
 *   post:
 *     summary: ยกเลิกคำสั่ง
 *     tags: [👤 Customer]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               reason:
 *                 type: string
 *     responses:
 *       200:
 *         description: ยกเลิกสำเร็จ
 */
app.post("/customer/orders/:id/cancel", async (req, res) => {
  const { reason } = req.body;
  const conn = await pool.getConnection();
  try {
    const [orderRows] = await conn.query(
      "SELECT id, status, table_id FROM orders WHERE id = ?",
      [req.params.id]
    );
    
    if (!orderRows.length) {
      return res.status(404).json({ error: "Order not found" });
    }

    const order = orderRows[0];

    if (['serving', 'paid'].includes(order.status)) {
      return res.status(400).json({ error: `Cannot cancel ${order.status} orders` });
    }

    await conn.beginTransaction();

    await conn.query(
      "UPDATE orders SET status = 'cancelled', updated_at = NOW() WHERE id = ?",
      [req.params.id]
    );

    await conn.query(
      "UPDATE restaurant_tables SET status = 'vacant', current_order_id = NULL, updated_at = NOW() WHERE table_id = ?",
      [order.table_id]
    );

    await conn.commit();
    res.json({ success: true, message: "Order cancelled successfully" });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: "Database server error" });
  } finally {
    conn.release();
  }
});

/**
 * @swagger
 * /customer/orders/{id}/receipt:
 *   get:
 *     summary: ดึงใบเสร็จ
 *     tags: [👤 Customer]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: ใบเสร็จ
 */
app.get("/customer/orders/:id/receipt", async (req, res) => {
  try {
    const [orders] = await pool.query(
      `SELECT id, table_id, subtotal, vat_amount, total, payment_method, paid_at, created_at, status
       FROM orders WHERE id = ?`,
      [req.params.id]
    );

    if (!orders.length) {
      return res.status(404).json({ error: "Order not found" });
    }

    const order = orders[0];

    const [items] = await pool.query(`
      SELECT 
        oi.id,
        oi.menu_name_th,
        mi.emoji,
        oi.unit_price,
        oi.qty,
        oi.extra_price,
        oi.line_total,
        GROUP_CONCAT(oit.topping_name SEPARATOR ', ') as toppings
      FROM order_items oi
      LEFT JOIN menu_items mi ON mi.id = oi.menu_id
      LEFT JOIN order_item_toppings oit ON oi.id = oit.order_item_id
      WHERE oi.order_id = ?
      GROUP BY oi.id
    `, [req.params.id]);

    res.json({
      order: {
        id: order.id,
        table_id: order.table_id,
        created_at: order.created_at,
        paid_at: order.paid_at,
        subtotal: parseFloat(order.subtotal),
        vat_amount: parseFloat(order.vat_amount),
        total: parseFloat(order.total),
        payment_method: order.payment_method,
        status: order.status
      },
      items: items
    });
  } catch (err) {
    res.status(500).json({ error: "Server Error" });
  }
});

/**
 * @swagger
 * /customer/reviews:
 *   post:
 *     summary: เพิ่มความเห็นใหม่
 *     tags: [👤 Customer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               orderId:
 *                 type: string
 *               tableId:
 *                 type: string
 *               sessionId:
 *                 type: string
 *               rating:
 *                 type: integer
 *               comment:
 *                 type: string
 *     responses:
 *       200:
 *         description: เพิ่มสำเร็จ
 */
app.post("/customer/reviews", async (req, res) => {
  const { orderId, tableId, rating, comment, sessionId } = req.body;
  try {
    const [result] = await pool.query(
      "INSERT INTO reviews (order_id, table_id, session_id, rating, comment) VALUES (?,?,?,?,?)",
      [orderId || null, tableId, sessionId || null, parseInt(rating), comment || ""]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /customer/reviews:
 *   get:
 *     summary: ดึงความเห็นทั้งหมด
 *     tags: [👤 Customer]
 *     responses:
 *       200:
 *         description: รายชื่อความเห็น
 */
app.get("/customer/reviews", async (_req, res) => {
  try {
    const [results] = await pool.query(
      `SELECT id, order_id AS orderId, table_id AS tableId, 
              session_id AS sessionId, rating, comment, 
              created_at AS createdAt 
       FROM reviews ORDER BY created_at DESC`
    );
    res.json(results);
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

/**
 * @swagger
 * /customer/history:
 *   get:
 *     summary: ดึงประวัติการสั่งซื้อของลูกค้า
 *     tags: [👤 Customer]
 *     parameters:
 *       - in: query
 *         name: sessionIds
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: ประวัติการสั่งซื้อ
 */
app.get("/customer/history", async (req, res) => {
  const { sessionIds } = req.query;
  if (!sessionIds) return res.json([]);

  const ids = sessionIds.split(',').filter(Boolean);
  if (!ids.length) return res.json([]);
  const placeholders = ids.map(() => '?').join(',');

  try {
    const [orders] = await pool.query(`
      SELECT o.id, o.session_id, o.table_id, o.status,
             o.subtotal, o.vat_amount, o.total,
             o.is_paid, o.payment_method, o.created_at, o.paid_at
      FROM orders o
      WHERE o.session_id IN (${placeholders})
      ORDER BY o.created_at DESC
    `, ids);

    if (!orders.length) return res.json([]);

    const orderIds = orders.map(o => o.id);
    const oPlaceholders = orderIds.map(() => '?').join(',');

    const [items] = await pool.query(`
      SELECT oi.id, oi.order_id, oi.menu_id,
             oi.menu_name_th AS name,
             mi.emoji AS img,
             oi.qty, oi.unit_price AS price,
             oi.line_total AS totalPrice,
             oi.special_note AS note
      FROM order_items oi
      LEFT JOIN menu_items mi ON mi.id = oi.menu_id
      WHERE oi.order_id IN (${oPlaceholders})
    `, orderIds);

    const itemIds = items.map(i => i.id);
    let toppingMap = {};
    if (itemIds.length) {
      const tPlaceholders = itemIds.map(() => '?').join(',');
      const [toppings] = await pool.query(
        `SELECT order_item_id, topping_name FROM order_item_toppings WHERE order_item_id IN (${tPlaceholders})`,
        itemIds
      );
      toppings.forEach(t => {
        if (!toppingMap[t.order_item_id]) toppingMap[t.order_item_id] = [];
        toppingMap[t.order_item_id].push(t.topping_name);
      });
    }

    const itemsByOrder = {};
    items.forEach(i => {
      if (!itemsByOrder[i.order_id]) itemsByOrder[i.order_id] = [];
      itemsByOrder[i.order_id].push({
        name: i.name,
        img: i.img || '🍽️',
        qty: i.qty,
        price: parseFloat(i.price),
        totalPrice: parseFloat(i.totalPrice),
        note: i.note || null,
        toppings: toppingMap[i.id] || [],
      });
    });

    const [reviews] = await pool.query(`
      SELECT session_id, rating, comment FROM reviews
      WHERE session_id IN (${placeholders})
    `, ids);

    const history = orders.map(o => {
      const review = reviews.find(r => r.session_id === o.session_id) || null;
      return {
        id: o.id,
        session_id: o.session_id,
        table_id: o.table_id,
        status: o.status,
        subtotal: parseFloat(o.subtotal),
        vat_amount: parseFloat(o.vat_amount),
        total: parseFloat(o.total),
        is_paid: o.is_paid,
        payment_method: o.payment_method,
        created_at: o.created_at,
        paid_at: o.paid_at,
        items: itemsByOrder[o.id] || [],
        review,
      };
    });

    res.json(history);
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

/**
 * @swagger
 * /customer/payments:
 *   get:
 *     summary: ดึงประวัติการชำระเงิน
 *     tags: [👤 Customer]
 *     parameters:
 *       - in: query
 *         name: sessions
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: ประวัติการชำระเงิน
 */
app.get("/customer/payments", async (req, res) => {
  const sessionIds = req.query.sessions?.split(',').filter(Boolean) || [];

  if (!sessionIds.length) {
    return res.json([]);
  }

  const placeholders = sessionIds.map(() => '?').join(',');

  try {
    const [payments] = await pool.query(`
      SELECT 
        o.id, 
        COUNT(DISTINCT oi.id) as item_count,
        o.total, 
        o.created_at,
        o.payment_method,
        rt.table_id
      FROM orders o
      LEFT JOIN order_items oi ON oi.order_id = o.id
      LEFT JOIN restaurant_tables rt ON o.table_id = rt.table_id
      WHERE o.session_id IN (${placeholders}) AND o.is_paid = TRUE
      GROUP BY o.id
      ORDER BY o.created_at DESC
      LIMIT 10
    `, sessionIds);

    res.json(payments || []);
  } catch (err) {
    res.status(500).json({ error: "Server Error" });
  }
});

// ============================================================
//  🍽️  MENU MANAGEMENT (ADMIN)
// ============================================================

function formatMenuItem(m) {
  return {
    id:        m.id,
    name:      m.name_en || m.name_th,
    name_th:   m.name_th,
    category:  m.category_code,
    price:     parseFloat(m.price),
    img:       m.emoji || "🍽️",
    available: m.is_available ? 1 : 0,
    toppings:  m.toppings || [],
  };
}

const MENU_SELECT = `
  SELECT
    mi.id, mi.name_th, mi.name_en, mi.price, mi.emoji, mi.is_available,
    mc.code AS category_code,
    GROUP_CONCAT(
      IF(mt.id IS NULL, NULL,
         CONCAT(mt.name_th, IF(mt.extra_price > 0, CONCAT(' (+', CAST(mt.extra_price AS CHAR), ')'), ''))
      )
      ORDER BY mt.sort_order SEPARATOR '||'
    ) AS toppings_raw
  FROM menu_items mi
  JOIN menu_categories mc ON mi.category_id = mc.id
  LEFT JOIN menu_toppings mt ON mt.menu_id = mi.id
  WHERE mi.is_deleted = FALSE
`;
const MENU_GROUP = " GROUP BY mi.id, mc.code ORDER BY mc.sort_order, mi.name_th";

function parseToppings(raw) {
  if (!raw) return [];
  return raw.split('||').map(t => t.trim()).filter(Boolean);
}

/**
 * @swagger
 * /admin/menu:
 *   post:
 *     summary: เพิ่มรายการอาหารใหม่
 *     tags: [👨‍💼 Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               name_th:
 *                 type: string
 *               category:
 *                 type: string
 *               price:
 *                 type: number
 *               img:
 *                 type: string
 *               toppings:
 *                 type: array
 *     responses:
 *       200:
 *         description: เพิ่มสำเร็จ
 */
app.post("/admin/menu", async (req, res) => {
  const { name, name_th, category, price, toppings, img } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [catRow] = await conn.query("SELECT id FROM menu_categories WHERE code = ?", [category]);
    if (!catRow.length) { await conn.rollback(); return res.status(400).send("Invalid category"); }

    const newId = `MN-${Date.now()}`;
    await conn.query(
      "INSERT INTO menu_items (id, category_id, name_th, name_en, price, emoji) VALUES (?,?,?,?,?,?)",
      [newId, catRow[0].id, name_th || name, name || name_th, parseFloat(price) || 0, img || "🍽️"]
    );

    const tops = Array.isArray(toppings) ? toppings : [];
    for (let i = 0; i < tops.length; i++) {
      const t = tops[i];
      const m = String(t).match(/\(\s*\+\s*([\d.]+)\s*\)/);
      const extra = m ? parseFloat(m[1]) : 0;
      const nameTh = String(t).replace(/\s*\(\s*\+\s*[\d.]+\s*\)/, "").trim();
      await conn.query(
        "INSERT INTO menu_toppings (menu_id, name_th, extra_price, sort_order) VALUES (?,?,?,?)",
        [newId, nameTh, extra, i]
      );
    }
    await conn.commit();
    res.json({ id: newId, name_th: name_th || name, category, price: parseFloat(price) || 0, toppings: tops, img: img || "🍽️", available: 1 });
  } catch (err) {
    await conn.rollback();
    res.status(500).send("Database server error");
  } finally {
    conn.release();
  }
});

/**
 * @swagger
 * /admin/menu/{id}:
 *   put:
 *     summary: แก้ไขรายการอาหาร
 *     tags: [👨‍💼 Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: แก้ไขสำเร็จ
 */
app.put("/admin/menu/:id", async (req, res) => {
  const { id } = req.params;
  const { name_th, nameTh, name, category, price, toppings, img, available } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const fields = [], vals = [];

    const thName = name_th || nameTh;
    if (thName)    { fields.push("name_th = ?");      vals.push(thName); }
    if (name)      { fields.push("name_en = ?");      vals.push(name); }
    if (price !== undefined) { fields.push("price = ?"); vals.push(parseFloat(price)); }
    if (img)       { fields.push("emoji = ?");        vals.push(img); }
    if (available !== undefined) { fields.push("is_available = ?"); vals.push(available ? 1 : 0); }

    if (category) {
      const [catRow] = await conn.query("SELECT id FROM menu_categories WHERE code = ?", [category]);
      if (catRow.length) { fields.push("category_id = ?"); vals.push(catRow[0].id); }
    }

    if (fields.length) {
      vals.push(id);
      await conn.query(`UPDATE menu_items SET ${fields.join(", ")} WHERE id = ?`, vals);
    }

    if (Array.isArray(toppings)) {
      await conn.query("DELETE FROM menu_toppings WHERE menu_id = ?", [id]);
      for (let i = 0; i < toppings.length; i++) {
        const t = toppings[i];
        const m = String(t).match(/\(\s*\+\s*([\d.]+)\s*\)/);
        const extra = m ? parseFloat(m[1]) : 0;
        const nameTh2 = String(t).replace(/\s*\(\s*\+\s*[\d.]+\s*\)/, "").trim();
        await conn.query(
          "INSERT INTO menu_toppings (menu_id, name_th, extra_price, sort_order) VALUES (?,?,?,?)",
          [id, nameTh2, extra, i]
        );
      }
    }
    await conn.commit();
    res.send("Update successfully");
  } catch (err) {
    await conn.rollback();
    res.status(500).send("Database server error");
  } finally {
    conn.release();
  }
});

/**
 * @swagger
 * /admin/menu/{id}:
 *   delete:
 *     summary: ลบรายการอาหาร
 *     tags: [👨‍💼 Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: ลบสำเร็จ
 */
app.delete("/admin/menu/:id", async (req, res) => {
  try {
    const [result] = await pool.query("UPDATE menu_items SET is_deleted = TRUE WHERE id = ?", [req.params.id]);
    if (result.affectedRows !== 1) return res.status(404).send("Menu not found");
    res.send("Delete successfully");
  } catch (err) {
    res.status(500).send("Database server error");
  }
});

// ============================================================
//  HELPER FUNCTIONS
// ============================================================

async function fetchOrdersWithItems(whereClause = "") {
  const [orders] = await pool.query(
    `SELECT o.id, o.table_id, o.session_id, o.status,
            o.subtotal, o.vat_amount, o.total,
            o.is_paid, o.payment_method, o.created_at, o.paid_at
     FROM orders o ${whereClause} ORDER BY o.created_at ASC`
  );
  if (!orders.length) return [];

  const orderIds = orders.map(o => o.id);
  const placeholders = orderIds.map(() => '?').join(',');

  const [items] = await pool.query(
    `SELECT oi.id, oi.order_id, oi.menu_id, oi.menu_name_th AS name,
            mi.emoji AS img, oi.qty, oi.unit_price AS price,
            oi.line_total AS totalPrice, oi.special_note AS note
     FROM order_items oi
     LEFT JOIN menu_items mi ON mi.id = oi.menu_id
     WHERE oi.order_id IN (${placeholders})`,
    orderIds
  );

  const itemIds = items.map(i => i.id);
  let toppingMap = {};
  if (itemIds.length) {
    const tPlaceholders = itemIds.map(() => '?').join(',');
    const [toppings] = await pool.query(
      `SELECT order_item_id, topping_name FROM order_item_toppings WHERE order_item_id IN (${tPlaceholders})`,
      itemIds
    );
    toppings.forEach(t => {
      if (!toppingMap[t.order_item_id]) toppingMap[t.order_item_id] = [];
      toppingMap[t.order_item_id].push(t.topping_name);
    });
  }

  const itemsByOrder = {};
  items.forEach(i => {
    if (!itemsByOrder[i.order_id]) itemsByOrder[i.order_id] = [];
    itemsByOrder[i.order_id].push({
      menuId:     i.menu_id,
      name:       i.name,
      img:        i.img || '🍽️',
      qty:        i.qty,
      price:      parseFloat(i.price),
      totalPrice: parseFloat(i.totalPrice),
      note:       i.note || null,
      toppings:   toppingMap[i.id] || [],
    });
  });

  return orders.map(o => ({
    id:        o.id,
    tableId:   o.table_id,
    sessionId: o.session_id,
    items:     itemsByOrder[o.id] || [],
    subtotal:  parseFloat(o.subtotal),
    total:     parseFloat(o.total),
    status:    o.status,
    paid:      o.is_paid ? 1 : 0,
    createdAt: o.created_at,
    paidAt:    o.paid_at,
  }));
}

// ============================================================
//  📄  PAGE ROUTES
// ============================================================

app.get("/",               (_req, res) => res.sendFile(path.join(__dirname, "views/table.html")));
app.get("/table",          (_req, res) => res.sendFile(path.join(__dirname, "views/table.html")));
app.get("/menu-page",      (_req, res) => res.sendFile(path.join(__dirname, "views/menu.html")));
app.get("/checkout",       (_req, res) => res.sendFile(path.join(__dirname, "views/checkout.html")));
app.get("/login",          (_req, res) => res.sendFile(path.join(__dirname, "views/login.html")));
app.get("/kitchen",        (_req, res) => res.sendFile(path.join(__dirname, "views/kitchen.html")));
app.get("/admin",          (_req, res) => res.sendFile(path.join(__dirname, "views/admin.html")));
app.get("/admin-tables",   (_req, res) => res.sendFile(path.join(__dirname, "views/admin-tables.html")));
app.get("/order-history",  (_req, res) => res.sendFile(path.join(__dirname, "views/order-history.html")));

// ============================================================
//  🔄 AUTO-CLEAN STUCK TABLES
// ============================================================

setInterval(async () => {
  try {
    const [result1] = await pool.query(`
      UPDATE restaurant_tables 
      SET status = 'vacant', current_order_id = NULL, updated_at = NOW()
      WHERE status = 'occupied' AND updated_at < DATE_SUB(NOW(), INTERVAL 2 HOUR)
    `);
    if (result1.affectedRows > 0) {
      console.log(`✅ Auto-released ${result1.affectedRows} stuck occupied tables`);
    }

    const [result2] = await pool.query(`
      UPDATE restaurant_tables 
      SET status = 'vacant', current_order_id = NULL, updated_at = NOW()
      WHERE status = 'cleaning' AND updated_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)
    `);
    if (result2.affectedRows > 0) {
      console.log(`✅ Auto-released ${result2.affectedRows} stuck cleaning tables`);
    }

    const [result3] = await pool.query(`
      UPDATE customer_sessions 
      SET is_active = 0, ended_at = NOW() 
      WHERE is_active = 1 AND created_at < DATE_SUB(NOW(), INTERVAL 3 HOUR)
    `);
    if (result3.affectedRows > 0) {
      console.log(`✅ Auto-closed ${result3.affectedRows} stuck sessions`);
    }
  } catch (e) {
    console.error("❌ Auto-maintenance error:", e.message);
  }
}, 300000);

// ============================================================
//  🚀  START SERVER
// ============================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════╗
║  🚀 HappyFood Server Running                           ║
║  🌐 http://localhost:${PORT}                              ║
║  📚 API Docs: http://localhost:${PORT}/api-docs           ║
║                                                        ║
║  👨‍💼 Admin Routes:    /admin/*                           ║
║  👨‍🍳 Chef Routes:     /chef/*                            ║
║  👤 Customer Routes: /customer/*                       ║
╚════════════════════════════════════════════════════════╝
  `);
});
