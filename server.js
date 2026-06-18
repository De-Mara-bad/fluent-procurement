try { require('dotenv').config(); } catch(e) {}
const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { query, initializeDatabase, generatePONumber } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'fluent-procurement-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 8 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId || req.session.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await query(`SELECT * FROM users WHERE email = $1 AND active = 1`, [email]);
    const user = r.rows[0];
    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid email or password' });
    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.name = user.name;
    req.session.buildingId = user.building_id;
    await query(`INSERT INTO activity_log (user_id, action) VALUES ($1, 'login')`, [user.id]);
    res.json({ role: user.role, name: user.name, buildingId: user.building_id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const r = await query(`SELECT id, name, email, role, building_id FROM users WHERE id = $1`, [req.session.userId]);
    const user = r.rows[0];
    let buildingName = null;
    if (user.building_id) {
      const b = await query(`SELECT name FROM buildings WHERE id = $1`, [user.building_id]);
      buildingName = b.rows[0]?.name;
    }
    res.json({ ...user, buildingName });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── BUILDINGS ─────────────────────────────────────────────────────────────────
app.get('/api/buildings', requireAuth, async (req, res) => {
  const r = await query(`SELECT * FROM buildings ORDER BY name`);
  res.json(r.rows);
});
app.post('/api/buildings', requireAdmin, async (req, res) => {
  const { name, address } = req.body;
  const r = await query(`INSERT INTO buildings (name, address) VALUES ($1, $2) RETURNING id`, [name, address || '']);
  res.json({ id: r.rows[0].id, name, address });
});
app.put('/api/buildings/:id', requireAdmin, async (req, res) => {
  const { name, address } = req.body;
  await query(`UPDATE buildings SET name=$1, address=$2 WHERE id=$3`, [name, address, req.params.id]);
  res.json({ ok: true });
});
app.delete('/api/buildings/:id', requireAdmin, async (req, res) => {
  await query(`DELETE FROM buildings WHERE id=$1`, [req.params.id]);
  res.json({ ok: true });
});

// ── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users', requireAdmin, async (req, res) => {
  const r = await query(`SELECT u.id, u.name, u.email, u.role, u.active, u.building_id, b.name as building_name, u.created_at FROM users u LEFT JOIN buildings b ON u.building_id = b.id ORDER BY u.name`);
  res.json(r.rows);
});
app.post('/api/users', requireAdmin, async (req, res) => {
  const { name, email, password, role, building_id } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  const r = await query(`INSERT INTO users (name, email, password, role, building_id) VALUES ($1,$2,$3,$4,$5) RETURNING id`, [name, email, hash, role, building_id || null]);
  res.json({ id: r.rows[0].id });
});
app.put('/api/users/:id', requireAdmin, async (req, res) => {
  const { name, email, role, building_id, active } = req.body;
  await query(`UPDATE users SET name=$1, email=$2, role=$3, building_id=$4, active=$5 WHERE id=$6`, [name, email, role, building_id || null, active ?? 1, req.params.id]);
  res.json({ ok: true });
});
app.put('/api/users/:id/password', requireAdmin, async (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 10);
  await query(`UPDATE users SET password=$1 WHERE id=$2`, [hash, req.params.id]);
  res.json({ ok: true });
});
app.put('/api/users/me/password', requireAuth, async (req, res) => {
  const { current, newPassword } = req.body;
  const r = await query(`SELECT password FROM users WHERE id=$1`, [req.session.userId]);
  if (!bcrypt.compareSync(current, r.rows[0].password)) return res.status(401).json({ error: 'Current password incorrect' });
  await query(`UPDATE users SET password=$1 WHERE id=$2`, [bcrypt.hashSync(newPassword, 10), req.session.userId]);
  res.json({ ok: true });
});

// ── SUPPLIERS ─────────────────────────────────────────────────────────────────
app.get('/api/suppliers', requireAuth, async (req, res) => {
  const where = req.query.all === 'true' ? '' : 'WHERE active = 1';
  const r = await query(`SELECT * FROM suppliers ${where} ORDER BY name`);
  res.json(r.rows);
});
app.post('/api/suppliers', requireAdmin, async (req, res) => {
  const { name, contact_person, email, phone, category, address, notes } = req.body;
  const r = await query(`INSERT INTO suppliers (name, contact_person, email, phone, category, address, notes) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, [name, contact_person, email, phone, category, address, notes]);
  res.json({ id: r.rows[0].id });
});
app.put('/api/suppliers/:id', requireAdmin, async (req, res) => {
  const { name, contact_person, email, phone, category, address, notes, active } = req.body;
  await query(`UPDATE suppliers SET name=$1, contact_person=$2, email=$3, phone=$4, category=$5, address=$6, notes=$7, active=$8 WHERE id=$9`, [name, contact_person, email, phone, category, address, notes, active ?? 1, req.params.id]);
  res.json({ ok: true });
});

// ── CATEGORIES ────────────────────────────────────────────────────────────────
app.get('/api/categories', requireAuth, async (req, res) => {
  const r = await query(`SELECT * FROM categories ORDER BY name`);
  res.json(r.rows);
});

// ── INVENTORY ─────────────────────────────────────────────────────────────────
app.get('/api/inventory', requireAuth, async (req, res) => {
  const buildingFilter = req.session.role === 'gm' ? `AND (i.building_id = ${req.session.buildingId} OR i.building_id IS NULL)` : '';
  const r = await query(`SELECT i.*, c.name as category_name, s.name as supplier_name, b.name as building_name FROM inventory_items i LEFT JOIN categories c ON i.category_id = c.id LEFT JOIN suppliers s ON i.supplier_id = s.id LEFT JOIN buildings b ON i.building_id = b.id WHERE 1=1 ${buildingFilter} ORDER BY i.name`);
  res.json(r.rows);
});
app.post('/api/inventory', requireAdmin, async (req, res) => {
  const { name, sku, category_id, supplier_id, unit, current_stock, min_stock, unit_cost, building_id, notes } = req.body;
  const r = await query(`INSERT INTO inventory_items (name, sku, category_id, supplier_id, unit, current_stock, min_stock, unit_cost, building_id, notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`, [name, sku||null, category_id||null, supplier_id||null, unit||'each', current_stock||0, min_stock||0, unit_cost||0, building_id||null, notes||'']);
  res.json({ id: r.rows[0].id });
});
app.put('/api/inventory/:id', requireAdmin, async (req, res) => {
  const { name, sku, category_id, supplier_id, unit, current_stock, min_stock, unit_cost, building_id, notes } = req.body;
  await query(`UPDATE inventory_items SET name=$1, sku=$2, category_id=$3, supplier_id=$4, unit=$5, current_stock=$6, min_stock=$7, unit_cost=$8, building_id=$9, notes=$10 WHERE id=$11`, [name, sku||null, category_id||null, supplier_id||null, unit||'each', current_stock||0, min_stock||0, unit_cost||0, building_id||null, notes||'', req.params.id]);
  res.json({ ok: true });
});
app.put('/api/inventory/:id/stock', requireAdmin, async (req, res) => {
  const { adjustment, reason } = req.body;
  await query(`UPDATE inventory_items SET current_stock = current_stock + $1 WHERE id = $2`, [adjustment, req.params.id]);
  await query(`INSERT INTO activity_log (user_id, action, entity_type, entity_id, details) VALUES ($1,'stock_adjust','inventory',$2,$3)`, [req.session.userId, req.params.id, `${adjustment > 0 ? '+' : ''}${adjustment} - ${reason || 'Manual adjustment'}`]);
  res.json({ ok: true });
});

// ── PURCHASE ORDERS ───────────────────────────────────────────────────────────
async function sendPONotification(poNumber, userName, buildingName) {
  const s = await query(`SELECT key, value FROM settings`);
  const settings = {};
  s.rows.forEach(r => settings[r.key] = r.value);
  if (!settings.smtp_host || !settings.notification_email) return;
  try {
    const transporter = nodemailer.createTransport({ host: settings.smtp_host, port: parseInt(settings.smtp_port)||587, secure: false, auth: { user: settings.smtp_user, pass: settings.smtp_pass } });
    await transporter.sendMail({ from: settings.smtp_from||settings.smtp_user, to: settings.notification_email, subject: `New Purchase Request - ${poNumber} | ${buildingName}`, html: `<h2>New Purchase Request</h2><p><strong>PO:</strong> ${poNumber}</p><p><strong>Building:</strong> ${buildingName}</p><p><strong>By:</strong> ${userName}</p>` });
  } catch(e) { console.error('Email failed:', e.message); }
}

app.get('/api/purchase-orders', requireAuth, async (req, res) => {
  try {
    const buildingFilter = req.session.role === 'gm' ? `AND po.building_id = ${req.session.buildingId}` : '';
    const statusFilter = req.query.status ? `AND po.status = '${req.query.status}'` : '';
    const r = await query(`SELECT po.*, b.name as building_name, u.name as requester_name, s.name as supplier_name, qu.name as quoted_by_name FROM purchase_orders po LEFT JOIN buildings b ON po.building_id = b.id LEFT JOIN users u ON po.requested_by = u.id LEFT JOIN suppliers s ON po.supplier_id = s.id LEFT JOIN users qu ON po.quoted_by = qu.id WHERE 1=1 ${buildingFilter} ${statusFilter} ORDER BY po.created_at DESC`);
    const orders = r.rows;
    for (const o of orders) {
      const items = await query(`SELECT pi.*, ii.name as item_name FROM po_items pi LEFT JOIN inventory_items ii ON pi.inventory_item_id = ii.id WHERE pi.po_id = $1`, [o.id]);
      o.items = items.rows;
    }
    res.json(orders);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/purchase-orders/:id', requireAuth, async (req, res) => {
  try {
    const r = await query(`SELECT po.*, b.name as building_name, u.name as requester_name, s.name as supplier_name FROM purchase_orders po LEFT JOIN buildings b ON po.building_id = b.id LEFT JOIN users u ON po.requested_by = u.id LEFT JOIN suppliers s ON po.supplier_id = s.id WHERE po.id = $1`, [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
    const po = r.rows[0];
    if (req.session.role === 'gm' && po.building_id != req.session.buildingId) return res.status(403).json({ error: 'Forbidden' });
    const items = await query(`SELECT pi.*, ii.name as item_name FROM po_items pi LEFT JOIN inventory_items ii ON pi.inventory_item_id = ii.id WHERE pi.po_id = $1`, [po.id]);
    po.items = items.rows;
    res.json(po);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/purchase-orders', requireAuth, async (req, res) => {
  try {
    const { supplier_id, notes, items } = req.body;
    const buildingId = req.session.role === 'gm' ? req.session.buildingId : req.body.building_id;
    if (!buildingId) return res.status(400).json({ error: 'Building required' });
    if (!items || items.length === 0) return res.status(400).json({ error: 'At least one item required' });
    const poNumber = await generatePONumber();
    const r = await query(`INSERT INTO purchase_orders (po_number, building_id, requested_by, supplier_id, notes) VALUES ($1,$2,$3,$4,$5) RETURNING id`, [poNumber, buildingId, req.session.userId, supplier_id||null, notes||'']);
    const poId = r.rows[0].id;
    for (const item of items) {
      await query(`INSERT INTO po_items (po_id, inventory_item_id, description, quantity, unit, category) VALUES ($1,$2,$3,$4,$5,$6)`, [poId, item.inventory_item_id||null, item.description, item.quantity||1, item.unit||'each', item.category||'']);
    }
    const building = await query(`SELECT name FROM buildings WHERE id=$1`, [buildingId]);
    await sendPONotification(poNumber, req.session.name, building.rows[0]?.name || '');
    await query(`INSERT INTO activity_log (user_id, action, entity_type, entity_id) VALUES ($1,'create_po','purchase_order',$2)`, [req.session.userId, poId]);
    res.json({ id: poId, po_number: poNumber });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/purchase-orders/:id/quote', requireAdmin, async (req, res) => {
  try {
    const { quote_amount, quote_notes, supplier_id, items } = req.body;
    await query(`UPDATE purchase_orders SET status='quoted', quote_amount=$1, quote_notes=$2, quoted_by=$3, quoted_at=NOW(), supplier_id=COALESCE($4, supplier_id), updated_at=NOW() WHERE id=$5`, [quote_amount, quote_notes||'', req.session.userId, supplier_id||null, req.params.id]);
    if (items) {
      for (const item of items) {
        await query(`UPDATE po_items SET unit_price=$1, total_price=$2 WHERE id=$3`, [item.unit_price, item.total_price, item.id]);
      }
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/purchase-orders/:id/status', requireAdmin, async (req, res) => {
  await query(`UPDATE purchase_orders SET status=$1, updated_at=NOW() WHERE id=$2`, [req.body.status, req.params.id]);
  res.json({ ok: true });
});

app.put('/api/purchase-orders/:id/cancel', requireAuth, async (req, res) => {
  const r = await query(`SELECT * FROM purchase_orders WHERE id=$1`, [req.params.id]);
  const po = r.rows[0];
  if (!po) return res.status(404).json({ error: 'Not found' });
  if (req.session.role === 'gm' && (po.building_id != req.session.buildingId || po.status !== 'pending')) return res.status(403).json({ error: 'Cannot cancel' });
  await query(`UPDATE purchase_orders SET status='cancelled', updated_at=NOW() WHERE id=$1`, [req.params.id]);
  res.json({ ok: true });
});

// ── SETTINGS ─────────────────────────────────────────────────────────────────
app.get('/api/settings', requireAdmin, async (req, res) => {
  const r = await query(`SELECT key, value FROM settings WHERE key != 'smtp_pass'`);
  const s = {};
  r.rows.forEach(row => s[row.key] = row.value);
  res.json(s);
});
app.put('/api/settings', requireAdmin, async (req, res) => {
  for (const [k, v] of Object.entries(req.body)) {
    await query(`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value=$2`, [k, v]);
  }
  res.json({ ok: true });
});

// ── XERO ──────────────────────────────────────────────────────────────────────
app.get('/api/xero/config', requireAdmin, async (req, res) => {
  const r = await query(`SELECT client_id, client_secret, tenant_id FROM xero_config WHERE id=1`);
  res.json(r.rows[0] || {});
});
app.put('/api/xero/config', requireAdmin, async (req, res) => {
  const { client_id, client_secret } = req.body;
  await query(`INSERT INTO xero_config (id, client_id, client_secret) VALUES (1,$1,$2) ON CONFLICT (id) DO UPDATE SET client_id=$1, client_secret=$2`, [client_id, client_secret]);
  res.json({ ok: true });
});
app.get('/api/xero/connect', requireAdmin, async (req, res) => {
  const r = await query(`SELECT client_id FROM xero_config WHERE id=1`);
  if (!r.rows[0]?.client_id) return res.status(400).json({ error: 'Xero client ID not configured' });
  const redirectUri = `${req.protocol}://${req.get('host')}/api/xero/callback`;
  res.redirect(`https://login.xero.com/identity/connect/authorize?response_type=code&client_id=${r.rows[0].client_id}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=openid profile email accounting.transactions offline_access&state=xero-connect`);
});
app.get('/api/xero/callback', requireAdmin, async (req, res) => {
  const { code } = req.query;
  const cfg = await query(`SELECT client_id, client_secret FROM xero_config WHERE id=1`);
  const redirectUri = `${req.protocol}://${req.get('host')}/api/xero/callback`;
  try {
    const tokenRes = await fetch('https://identity.xero.com/connect/token', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded','Authorization':'Basic '+Buffer.from(`${cfg.rows[0].client_id}:${cfg.rows[0].client_secret}`).toString('base64')}, body: new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:redirectUri}) });
    const tokens = await tokenRes.json();
    const tenantRes = await fetch('https://api.xero.com/connections', { headers:{'Authorization':`Bearer ${tokens.access_token}`} });
    const tenants = await tenantRes.json();
    await query(`UPDATE xero_config SET access_token=$1, refresh_token=$2, token_expires_at=$3, tenant_id=$4 WHERE id=1`, [tokens.access_token, tokens.refresh_token, new Date(Date.now()+tokens.expires_in*1000), tenants[0]?.tenantId]);
    res.redirect('/#/admin/xero?connected=true');
  } catch(e) { res.redirect('/#/admin/xero?error=true'); }
});
app.post('/api/xero/export/:poId', requireAdmin, async (req, res) => {
  const po = await query(`SELECT po.*, s.name as supplier_name FROM purchase_orders po LEFT JOIN suppliers s ON po.supplier_id=s.id WHERE po.id=$1`, [req.params.poId]);
  if (!po.rows[0]) return res.status(404).json({ error: 'Not found' });
  const items = await query(`SELECT * FROM po_items WHERE po_id=$1`, [req.params.poId]);
  const cfg = await query(`SELECT * FROM xero_config WHERE id=1`);
  if (!cfg.rows[0]?.access_token) return res.status(400).json({ error: 'Xero not connected' });
  try {
    const response = await fetch('https://api.xero.com/api.xro/2.0/PurchaseOrders', { method:'PUT', headers:{'Authorization':`Bearer ${cfg.rows[0].access_token}`,'Xero-Tenant-Id':cfg.rows[0].tenant_id,'Content-Type':'application/json'}, body: JSON.stringify({PurchaseOrders:[{Contact:{Name:po.rows[0].supplier_name||'Unknown'},Date:new Date().toISOString().split('T')[0],LineItems:items.rows.map(i=>({Description:i.description,Quantity:i.quantity,UnitAmount:i.unit_price||0,AccountCode:'310'})),Reference:po.rows[0].po_number,Status:'DRAFT'}]}) });
    const data = await response.json();
    if (data.PurchaseOrders?.[0]?.PurchaseOrderID) {
      await query(`UPDATE purchase_orders SET xero_invoice_id=$1 WHERE id=$2`, [data.PurchaseOrders[0].PurchaseOrderID, req.params.poId]);
      res.json({ ok: true, xeroId: data.PurchaseOrders[0].PurchaseOrderID });
    } else { res.status(400).json({ error: 'Xero export failed', details: data }); }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DASHBOARD STATS ───────────────────────────────────────────────────────────
app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
  try {
    const bf = req.session.role === 'gm' ? `AND building_id = ${req.session.buildingId}` : '';
    const [total, pending, quoted, approved, ordered, delivered] = await Promise.all([
      query(`SELECT COUNT(*) as c FROM purchase_orders WHERE 1=1 ${bf}`),
      query(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='pending' ${bf}`),
      query(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='quoted' ${bf}`),
      query(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='approved' ${bf}`),
      query(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='ordered' ${bf}`),
      query(`SELECT COUNT(*) as c FROM purchase_orders WHERE status='delivered' ${bf}`),
    ]);
    const stats = { total: parseInt(total.rows[0].c), pending: parseInt(pending.rows[0].c), quoted: parseInt(quoted.rows[0].c), approved: parseInt(approved.rows[0].c), ordered: parseInt(ordered.rows[0].c), delivered: parseInt(delivered.rows[0].c) };
    if (req.session.role === 'admin') {
      const [ls, sup, bld, usr] = await Promise.all([
        query(`SELECT COUNT(*) as c FROM inventory_items WHERE current_stock <= min_stock AND min_stock > 0`),
        query(`SELECT COUNT(*) as c FROM suppliers WHERE active=1`),
        query(`SELECT COUNT(*) as c FROM buildings`),
        query(`SELECT COUNT(*) as c FROM users WHERE active=1`),
      ]);
      stats.low_stock = parseInt(ls.rows[0].c);
      stats.suppliers = parseInt(sup.rows[0].c);
      stats.buildings = parseInt(bld.rows[0].c);
      stats.users = parseInt(usr.rows[0].c);
    }
    res.json(stats);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SPA ───────────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── START ─────────────────────────────────────────────────────────────────────
initializeDatabase().then(() => {
  app.listen(PORT, () => console.log('Fluent Procurement running on port ' + PORT));
}).catch(err => {
  console.error('Database init failed:', err);
  process.exit(1);
});
