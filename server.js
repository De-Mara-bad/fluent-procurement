try { require('dotenv').config(); } catch(e) {}
const express = require('express');
const session = require('express-session');
const path = require('path');
const { db, initializeDatabase } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database
initializeDatabase();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'fluent-procurement-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000 // 8 hours
  }
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId || req.session.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ─── AUTH ROUTES ───────────────────────────────────────────────────────────────
const bcrypt = require('bcryptjs');

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare(`SELECT * FROM users WHERE email = ? AND active = 1`).get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  req.session.userId = user.id;
  req.session.role = user.role;
  req.session.name = user.name;
  req.session.buildingId = user.building_id;

  db.prepare(`INSERT INTO activity_log (user_id, action) VALUES (?, 'login')`).run(user.id);
  res.json({ role: user.role, name: user.name, buildingId: user.building_id });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare(`SELECT id, name, email, role, building_id FROM users WHERE id = ?`).get(req.session.userId);
  const building = user.building_id ? db.prepare(`SELECT name FROM buildings WHERE id = ?`).get(user.building_id) : null;
  res.json({ ...user, buildingName: building?.name });
});

// ─── BUILDINGS ─────────────────────────────────────────────────────────────────
app.get('/api/buildings', requireAuth, (req, res) => {
  res.json(db.prepare(`SELECT * FROM buildings ORDER BY name`).all());
});
app.post('/api/buildings', requireAdmin, (req, res) => {
  const { name, address } = req.body;
  const r = db.prepare(`INSERT INTO buildings (name, address) VALUES (?, ?)`).run(name, address || '');
  res.json({ id: r.lastInsertRowid, name, address });
});
app.put('/api/buildings/:id', requireAdmin, (req, res) => {
  const { name, address } = req.body;
  db.prepare(`UPDATE buildings SET name = ?, address = ? WHERE id = ?`).run(name, address, req.params.id);
  res.json({ ok: true });
});
app.delete('/api/buildings/:id', requireAdmin, (req, res) => {
  db.prepare(`DELETE FROM buildings WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

// ─── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users', requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.active, u.building_id, b.name as building_name, u.created_at
    FROM users u LEFT JOIN buildings b ON u.building_id = b.id ORDER BY u.name
  `).all();
  res.json(users);
});
app.post('/api/users', requireAdmin, (req, res) => {
  const { name, email, password, role, building_id } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  const r = db.prepare(`INSERT INTO users (name, email, password, role, building_id) VALUES (?, ?, ?, ?, ?)`).run(name, email, hash, role, building_id || null);
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/users/:id', requireAdmin, (req, res) => {
  const { name, email, role, building_id, active } = req.body;
  db.prepare(`UPDATE users SET name=?, email=?, role=?, building_id=?, active=? WHERE id=?`).run(name, email, role, building_id || null, active ?? 1, req.params.id);
  res.json({ ok: true });
});
app.put('/api/users/:id/password', requireAdmin, (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 10);
  db.prepare(`UPDATE users SET password = ? WHERE id = ?`).run(hash, req.params.id);
  res.json({ ok: true });
});
app.put('/api/users/me/password', requireAuth, (req, res) => {
  const { current, newPassword } = req.body;
  const user = db.prepare(`SELECT password FROM users WHERE id = ?`).get(req.session.userId);
  if (!bcrypt.compareSync(current, user.password)) return res.status(401).json({ error: 'Current password incorrect' });
  db.prepare(`UPDATE users SET password = ? WHERE id = ?`).run(bcrypt.hashSync(newPassword, 10), req.session.userId);
  res.json({ ok: true });
});

// ─── SUPPLIERS ─────────────────────────────────────────────────────────────────
app.get('/api/suppliers', requireAuth, (req, res) => {
  const active = req.query.all === 'true' ? '' : 'WHERE active = 1';
  res.json(db.prepare(`SELECT * FROM suppliers ${active} ORDER BY name`).all());
});
app.post('/api/suppliers', requireAdmin, (req, res) => {
  const { name, contact_person, email, phone, category, address, notes } = req.body;
  const r = db.prepare(`INSERT INTO suppliers (name, contact_person, email, phone, category, address, notes) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(name, contact_person, email, phone, category, address, notes);
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/suppliers/:id', requireAdmin, (req, res) => {
  const { name, contact_person, email, phone, category, address, notes, active } = req.body;
  db.prepare(`UPDATE suppliers SET name=?, contact_person=?, email=?, phone=?, category=?, address=?, notes=?, active=? WHERE id=?`)
    .run(name, contact_person, email, phone, category, address, notes, active ?? 1, req.params.id);
  res.json({ ok: true });
});

// ─── CATEGORIES ────────────────────────────────────────────────────────────────
app.get('/api/categories', requireAuth, (req, res) => {
  res.json(db.prepare(`SELECT * FROM categories ORDER BY name`).all());
});

// ─── INVENTORY ─────────────────────────────────────────────────────────────────
app.get('/api/inventory', requireAuth, (req, res) => {
  const buildingFilter = req.session.role === 'gm' ? `AND (i.building_id = ${req.session.buildingId} OR i.building_id IS NULL)` : '';
  const items = db.prepare(`
    SELECT i.*, c.name as category_name, s.name as supplier_name, b.name as building_name
    FROM inventory_items i
    LEFT JOIN categories c ON i.category_id = c.id
    LEFT JOIN suppliers s ON i.supplier_id = s.id
    LEFT JOIN buildings b ON i.building_id = b.id
    WHERE 1=1 ${buildingFilter}
    ORDER BY i.name
  `).all();
  res.json(items);
});
app.post('/api/inventory', requireAdmin, (req, res) => {
  const { name, sku, category_id, supplier_id, unit, current_stock, min_stock, unit_cost, building_id, notes } = req.body;
  const r = db.prepare(`INSERT INTO inventory_items (name, sku, category_id, supplier_id, unit, current_stock, min_stock, unit_cost, building_id, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(name, sku || null, category_id || null, supplier_id || null, unit || 'each', current_stock || 0, min_stock || 0, unit_cost || 0, building_id || null, notes || '');
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/inventory/:id', requireAdmin, (req, res) => {
  const { name, sku, category_id, supplier_id, unit, current_stock, min_stock, unit_cost, building_id, notes } = req.body;
  db.prepare(`UPDATE inventory_items SET name=?, sku=?, category_id=?, supplier_id=?, unit=?, current_stock=?, min_stock=?, unit_cost=?, building_id=?, notes=? WHERE id=?`)
    .run(name, sku || null, category_id || null, supplier_id || null, unit || 'each', current_stock || 0, min_stock || 0, unit_cost || 0, building_id || null, notes || '', req.params.id);
  res.json({ ok: true });
});
app.put('/api/inventory/:id/stock', requireAdmin, (req, res) => {
  const { adjustment, reason } = req.body;
  db.prepare(`UPDATE inventory_items SET current_stock = current_stock + ? WHERE id = ?`).run(adjustment, req.params.id);
  db.prepare(`INSERT INTO activity_log (user_id, action, entity_type, entity_id, details) VALUES (?, 'stock_adjust', 'inventory', ?, ?)`)
    .run(req.session.userId, req.params.id, `${adjustment > 0 ? '+' : ''}${adjustment} - ${reason || 'Manual adjustment'}`);
  res.json({ ok: true });
});

// ─── PURCHASE ORDERS ───────────────────────────────────────────────────────────
const nodemailer = require('nodemailer');

async function sendPONotification(po, user, building) {
  const settings = {};
  db.prepare(`SELECT key, value FROM settings`).all().forEach(r => settings[r.key] = r.value);
  if (!settings.smtp_host || !settings.notification_email) return;
  try {
    const transporter = nodemailer.createTransport({
      host: settings.smtp_host,
      port: parseInt(settings.smtp_port) || 587,
      secure: false,
      auth: { user: settings.smtp_user, pass: settings.smtp_pass }
    });
    await transporter.sendMail({
      from: settings.smtp_from || settings.smtp_user,
      to: settings.notification_email,
      subject: `New Purchase Request - ${po.po_number} | ${building}`,
      html: `
        <h2>New Purchase Request</h2>
        <p><strong>PO Number:</strong> ${po.po_number}</p>
        <p><strong>Building:</strong> ${building}</p>
        <p><strong>Requested by:</strong> ${user}</p>
        <p><strong>Date:</strong> ${new Date().toLocaleDateString()}</p>
        <p>Please log in to the Procurement System to review and provide a quote.</p>
      `
    });
  } catch (e) {
    console.error('Email send failed:', e.message);
  }
}

app.get('/api/purchase-orders', requireAuth, (req, res) => {
  const buildingFilter = req.session.role === 'gm' ? `AND po.building_id = ${req.session.buildingId}` : '';
  const statusFilter = req.query.status ? `AND po.status = '${req.query.status}'` : '';
  const orders = db.prepare(`
    SELECT po.*, b.name as building_name, u.name as requester_name, s.name as supplier_name,
           qu.name as quoted_by_name
    FROM purchase_orders po
    LEFT JOIN buildings b ON po.building_id = b.id
    LEFT JOIN users u ON po.requested_by = u.id
    LEFT JOIN suppliers s ON po.supplier_id = s.id
    LEFT JOIN users qu ON po.quoted_by = qu.id
    WHERE 1=1 ${buildingFilter} ${statusFilter}
    ORDER BY po.created_at DESC
  `).all();
  // Attach line items
  orders.forEach(o => {
    o.items = db.prepare(`
      SELECT pi.*, ii.name as item_name
      FROM po_items pi LEFT JOIN inventory_items ii ON pi.inventory_item_id = ii.id
      WHERE pi.po_id = ?
    `).all(o.id);
  });
  res.json(orders);
});

app.get('/api/purchase-orders/:id', requireAuth, (req, res) => {
  const po = db.prepare(`
    SELECT po.*, b.name as building_name, u.name as requester_name, s.name as supplier_name
    FROM purchase_orders po
    LEFT JOIN buildings b ON po.building_id = b.id
    LEFT JOIN users u ON po.requested_by = u.id
    LEFT JOIN suppliers s ON po.supplier_id = s.id
    WHERE po.id = ?
  `).get(req.params.id);
  if (!po) return res.status(404).json({ error: 'Not found' });
  if (req.session.role === 'gm' && po.building_id !== req.session.buildingId) return res.status(403).json({ error: 'Forbidden' });
  po.items = db.prepare(`SELECT pi.*, ii.name as item_name FROM po_items pi LEFT JOIN inventory_items ii ON pi.inventory_item_id = ii.id WHERE pi.po_id = ?`).all(po.id);
  res.json(po);
});

const { generatePONumber } = require('./database');

app.post('/api/purchase-orders', requireAuth, async (req, res) => {
  const { supplier_id, notes, items } = req.body;
  const buildingId = req.session.role === 'gm' ? req.session.buildingId : req.body.building_id;
  if (!buildingId) return res.status(400).json({ error: 'Building required' });
  if (!items || items.length === 0) return res.status(400).json({ error: 'At least one item required' });

  const poNumber = generatePONumber(db);
  const r = db.prepare(`INSERT INTO purchase_orders (po_number, building_id, requested_by, supplier_id, notes) VALUES (?, ?, ?, ?, ?)`)
    .run(poNumber, buildingId, req.session.userId, supplier_id || null, notes || '');
  const poId = r.lastInsertRowid;

  const insertItem = db.prepare(`INSERT INTO po_items (po_id, inventory_item_id, description, quantity, unit, category) VALUES (?, ?, ?, ?, ?, ?)`);
  items.forEach(item => insertItem.run(poId, item.inventory_item_id || null, item.description, item.quantity || 1, item.unit || 'each', item.category || ''));

  const building = db.prepare(`SELECT name FROM buildings WHERE id = ?`).get(buildingId);
  await sendPONotification({ po_number: poNumber }, req.session.name, building?.name || '');

  db.prepare(`INSERT INTO activity_log (user_id, action, entity_type, entity_id) VALUES (?, 'create_po', 'purchase_order', ?)`).run(req.session.userId, poId);
  res.json({ id: poId, po_number: poNumber });
});

// Admin: provide quote
app.put('/api/purchase-orders/:id/quote', requireAdmin, (req, res) => {
  const { quote_amount, quote_notes, supplier_id } = req.body;
  db.prepare(`UPDATE purchase_orders SET status='quoted', quote_amount=?, quote_notes=?, quoted_by=?, quoted_at=CURRENT_TIMESTAMP, supplier_id=COALESCE(?, supplier_id), updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .run(quote_amount, quote_notes || '', req.session.userId, supplier_id || null, req.params.id);

  // Update line item prices if provided
  if (req.body.items) {
    req.body.items.forEach(item => {
      db.prepare(`UPDATE po_items SET unit_price=?, total_price=? WHERE id=?`).run(item.unit_price, item.total_price, item.id);
    });
  }
  res.json({ ok: true });
});

// Update PO status
app.put('/api/purchase-orders/:id/status', requireAdmin, (req, res) => {
  const { status } = req.body;
  db.prepare(`UPDATE purchase_orders SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(status, req.params.id);
  res.json({ ok: true });
});

// Cancel PO (GM can cancel their own pending PO)
app.put('/api/purchase-orders/:id/cancel', requireAuth, (req, res) => {
  const po = db.prepare(`SELECT * FROM purchase_orders WHERE id = ?`).get(req.params.id);
  if (!po) return res.status(404).json({ error: 'Not found' });
  if (req.session.role === 'gm' && (po.building_id !== req.session.buildingId || po.status !== 'pending')) {
    return res.status(403).json({ error: 'Cannot cancel this order' });
  }
  db.prepare(`UPDATE purchase_orders SET status='cancelled', updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(req.params.id);
  res.json({ ok: true });
});

// ─── SETTINGS ──────────────────────────────────────────────────────────────────
app.get('/api/settings', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT key, value FROM settings WHERE key != 'smtp_pass'`).all();
  const s = {};
  rows.forEach(r => s[r.key] = r.value);
  res.json(s);
});
app.put('/api/settings', requireAdmin, (req, res) => {
  const upsert = db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`);
  Object.entries(req.body).forEach(([k, v]) => upsert.run(k, v));
  res.json({ ok: true });
});

// ─── XERO ──────────────────────────────────────────────────────────────────────
app.get('/api/xero/config', requireAdmin, (req, res) => {
  const cfg = db.prepare(`SELECT client_id, client_secret, tenant_id FROM xero_config WHERE id = 1`).get();
  res.json(cfg || {});
});
app.put('/api/xero/config', requireAdmin, (req, res) => {
  const { client_id, client_secret } = req.body;
  db.prepare(`INSERT OR REPLACE INTO xero_config (id, client_id, client_secret) VALUES (1, ?, ?)`).run(client_id, client_secret);
  res.json({ ok: true });
});

// Xero OAuth - redirect to Xero
app.get('/api/xero/connect', requireAdmin, (req, res) => {
  const cfg = db.prepare(`SELECT client_id FROM xero_config WHERE id = 1`).get();
  if (!cfg?.client_id) return res.status(400).json({ error: 'Xero client ID not configured' });
  const redirectUri = `${req.protocol}://${req.get('host')}/api/xero/callback`;
  const url = `https://login.xero.com/identity/connect/authorize?response_type=code&client_id=${cfg.client_id}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=openid profile email accounting.transactions offline_access&state=xero-connect`;
  res.redirect(url);
});

app.get('/api/xero/callback', requireAdmin, async (req, res) => {
  const { code } = req.query;
  const cfg = db.prepare(`SELECT client_id, client_secret FROM xero_config WHERE id = 1`).get();
  const redirectUri = `${req.protocol}://${req.get('host')}/api/xero/callback`;
  try {
    const tokenRes = await fetch('https://identity.xero.com/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + Buffer.from(`${cfg.client_id}:${cfg.client_secret}`).toString('base64') },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri })
    });
    const tokens = await tokenRes.json();
    const expires = new Date(Date.now() + tokens.expires_in * 1000).toISOString();
    // Get tenant ID
    const tenantRes = await fetch('https://api.xero.com/connections', { headers: { 'Authorization': `Bearer ${tokens.access_token}` } });
    const tenants = await tenantRes.json();
    const tenantId = tenants[0]?.tenantId;
    db.prepare(`UPDATE xero_config SET access_token=?, refresh_token=?, token_expires_at=?, tenant_id=? WHERE id=1`)
      .run(tokens.access_token, tokens.refresh_token, expires, tenantId);
    res.redirect('/#/admin/xero?connected=true');
  } catch (e) {
    res.redirect('/#/admin/xero?error=true');
  }
});

// Export PO to Xero
app.post('/api/xero/export/:poId', requireAdmin, async (req, res) => {
  const po = db.prepare(`SELECT po.*, s.name as supplier_name FROM purchase_orders po LEFT JOIN suppliers s ON po.supplier_id = s.id WHERE po.id = ?`).get(req.params.poId);
  if (!po) return res.status(404).json({ error: 'PO not found' });
  const items = db.prepare(`SELECT * FROM po_items WHERE po_id = ?`).all(po.id);
  const cfg = db.prepare(`SELECT * FROM xero_config WHERE id = 1`).get();
  if (!cfg?.access_token) return res.status(400).json({ error: 'Xero not connected' });

  const lineItems = items.map(i => ({
    Description: i.description,
    Quantity: i.quantity,
    UnitAmount: i.unit_price || 0,
    AccountCode: '310'
  }));

  try {
    const response = await fetch('https://api.xero.com/api.xro/2.0/PurchaseOrders', {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${cfg.access_token}`,
        'Xero-Tenant-Id': cfg.tenant_id,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        PurchaseOrders: [{
          Contact: { Name: po.supplier_name || 'Unknown Supplier' },
          Date: new Date().toISOString().split('T')[0],
          DeliveryDate: null,
          LineItems: lineItems,
          Reference: po.po_number,
          Status: 'DRAFT'
        }]
      })
    });
    const data = await response.json();
    if (data.PurchaseOrders?.[0]?.PurchaseOrderID) {
      const xeroId = data.PurchaseOrders[0].PurchaseOrderID;
      db.prepare(`UPDATE purchase_orders SET xero_invoice_id = ? WHERE id = ?`).run(xeroId, po.id);
      res.json({ ok: true, xeroId });
    } else {
      res.status(400).json({ error: 'Xero export failed', details: data });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── DASHBOARD STATS ───────────────────────────────────────────────────────────
app.get('/api/dashboard/stats', requireAuth, (req, res) => {
  const buildingFilter = req.session.role === 'gm' ? `AND building_id = ${req.session.buildingId}` : '';
  const stats = {
    total: db.prepare(`SELECT COUNT(*) as c FROM purchase_orders WHERE 1=1 ${buildingFilter}`).get().c,
    pending: db.prepare(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='pending' ${buildingFilter}`).get().c,
    quoted: db.prepare(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='quoted' ${buildingFilter}`).get().c,
    approved: db.prepare(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='approved' ${buildingFilter}`).get().c,
    ordered: db.prepare(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='ordered' ${buildingFilter}`).get().c,
    delivered: db.prepare(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='delivered' ${buildingFilter}`).get().c,
  };
  if (req.session.role === 'admin') {
    stats.low_stock = db.prepare(`SELECT COUNT(*) as c FROM inventory_items WHERE current_stock <= min_stock AND min_stock > 0`).get().c;
    stats.suppliers = db.prepare(`SELECT COUNT(*) as c FROM suppliers WHERE active = 1`).get().c;
    stats.buildings = db.prepare(`SELECT COUNT(*) as c FROM buildings`).get().c;
    stats.users = db.prepare(`SELECT COUNT(*) as c FROM users WHERE active = 1`).get().c;
  }
  res.json(stats);
});

// ─── SERVE SPA ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('Fluent Procurement running on port ' + PORT);
});