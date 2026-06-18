const { DatabaseSync: Database } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'procurement.db');

// Ensure the data directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);

// Enable foreign keys
db.exec('PRAGMA foreign_keys = ON');

function initializeDatabase() {
  db.exec(`
    -- Buildings/Properties
    CREATE TABLE IF NOT EXISTS buildings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Users (GMs and Admin)
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'gm')),
      building_id INTEGER REFERENCES buildings(id),
      active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Suppliers
    CREATE TABLE IF NOT EXISTS suppliers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      contact_person TEXT,
      email TEXT,
      phone TEXT,
      category TEXT,
      address TEXT,
      notes TEXT,
      active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Supply Categories
    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      description TEXT
    );

    -- Inventory Items (master list)
    CREATE TABLE IF NOT EXISTS inventory_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      sku TEXT UNIQUE,
      category_id INTEGER REFERENCES categories(id),
      supplier_id INTEGER REFERENCES suppliers(id),
      unit TEXT DEFAULT 'each',
      current_stock INTEGER DEFAULT 0,
      min_stock INTEGER DEFAULT 0,
      unit_cost REAL DEFAULT 0,
      building_id INTEGER REFERENCES buildings(id),
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Purchase Orders
    CREATE TABLE IF NOT EXISTS purchase_orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      po_number TEXT NOT NULL UNIQUE,
      building_id INTEGER REFERENCES buildings(id),
      requested_by INTEGER REFERENCES users(id),
      supplier_id INTEGER REFERENCES suppliers(id),
      status TEXT DEFAULT 'pending' CHECK(status IN ('pending','quoted','approved','ordered','delivered','cancelled')),
      notes TEXT,
      quote_amount REAL,
      quote_notes TEXT,
      quoted_by INTEGER REFERENCES users(id),
      quoted_at DATETIME,
      xero_invoice_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Purchase Order Line Items
    CREATE TABLE IF NOT EXISTS po_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      po_id INTEGER NOT NULL REFERENCES purchase_orders(id) ON DELETE CASCADE,
      inventory_item_id INTEGER REFERENCES inventory_items(id),
      description TEXT NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      unit TEXT DEFAULT 'each',
      unit_price REAL,
      total_price REAL,
      category TEXT
    );

    -- Settings
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    -- Xero Config
    CREATE TABLE IF NOT EXISTS xero_config (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      client_id TEXT,
      client_secret TEXT,
      tenant_id TEXT,
      access_token TEXT,
      refresh_token TEXT,
      token_expires_at DATETIME
    );

    -- Activity Log
    CREATE TABLE IF NOT EXISTS activity_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id INTEGER,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Seed default categories
  const cats = ['Building & Maintenance', 'Equipment', 'Housekeeping & Cleaning', 'Linen & Bedding', 'Food & Beverage', 'Office Supplies', 'Guest Amenities', 'Safety & Security', 'IT & Technology', 'Other'];
  const insertCat = db.prepare(`INSERT OR IGNORE INTO categories (name) VALUES (?)`);
  cats.forEach(c => insertCat.run(c));

  // Seed default settings
  const insertSetting = db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`);
  insertSetting.run('notification_email', 'finance@fluentliving.com');
  insertSetting.run('company_name', 'Fluent Living');
  insertSetting.run('po_prefix', 'FL-PO');
  insertSetting.run('smtp_host', '');
  insertSetting.run('smtp_port', '587');
  insertSetting.run('smtp_user', '');
  insertSetting.run('smtp_pass', '');
  insertSetting.run('smtp_from', '');

  // Seed admin user if none exists
  const adminExists = db.prepare(`SELECT id FROM users WHERE role = 'admin' LIMIT 1`).get();
  if (!adminExists) {
    const hash = bcrypt.hashSync('Admin@2024!', 10);
    db.prepare(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')`)
      .run('De-Mara', 'finance@fluentliving.com', hash);
    console.log('✅ Admin user created: finance@fluentliving.com / Admin@2024!');
  }

  // Seed sample suppliers
  const supplierCount = db.prepare(`SELECT COUNT(*) as c FROM suppliers`).get();
  if (supplierCount.c === 0) {
    const suppliers = [
      ['CleanPro Supplies', 'John Smith', 'orders@cleanpro.co.za', '011 123 4567', 'Housekeeping & Cleaning'],
      ['Linen World', 'Sarah Jones', 'sarah@linenworld.co.za', '021 456 7890', 'Linen & Bedding'],
      ['TechEquip SA', 'Mike Brown', 'mike@techequip.co.za', '011 987 6543', 'IT & Technology'],
      ['Hospitality Depot', 'Lisa White', 'lisa@hospdepot.co.za', '031 321 6540', 'Guest Amenities'],
      ['BuildRight SA', 'Tom Green', 'tom@buildright.co.za', '011 555 4321', 'Building & Maintenance'],
      ['Office Essentials', 'Anna Blue', 'anna@officeessentials.co.za', '021 789 0123', 'Office Supplies'],
      ['SafeGuard Solutions', 'Peter Black', 'peter@safeguard.co.za', '011 222 3333', 'Safety & Security'],
      ['CaterSupply', 'Mary Pink', 'mary@cater.co.za', '031 444 5555', 'Food & Beverage'],
      ['Ecolab SA', 'Chris Red', 'chris@ecolab.co.za', '011 666 7777', 'Housekeeping & Cleaning'],
      ['Makro Business', 'David Grey', 'david@makro.co.za', '012 888 9999', 'Office Supplies'],
      ['SA Hotel Supplies', 'Emma Purple', 'emma@sahotel.co.za', '021 111 2222', 'Guest Amenities'],
      ['Steelcase Furniture', 'Frank Orange', 'frank@steelcase.co.za', '011 333 4444', 'Equipment'],
      ['Plumbfix SA', 'Grace Yellow', 'grace@plumbfix.co.za', '021 555 6666', 'Building & Maintenance'],
      ['ElectroSafe', 'Henry Teal', 'henry@electrosafe.co.za', '011 777 8888', 'Building & Maintenance'],
      ['Medpet SA', 'Iris Cyan', 'iris@medpet.co.za', '031 999 0000', 'Safety & Security'],
      ['Fresh & Clean', 'Jack Lime', 'jack@freshclean.co.za', '011 000 1111', 'Housekeeping & Cleaning'],
      ['Premier Linens', 'Kate Navy', 'kate@premierlinens.co.za', '021 222 3333', 'Linen & Bedding'],
      ['Smart Systems', 'Leo Maroon', 'leo@smartsystems.co.za', '011 444 5555', 'IT & Technology'],
      ['Cape Catering Supplies', 'Mia Silver', 'mia@capecater.co.za', '021 666 7777', 'Food & Beverage'],
      ['National Hygiene', 'Noah Gold', 'noah@nathygiene.co.za', '011 888 9999', 'Housekeeping & Cleaning'],
    ];
    const insertSup = db.prepare(`INSERT INTO suppliers (name, contact_person, email, phone, category) VALUES (?, ?, ?, ?, ?)`);
    suppliers.forEach(s => insertSup.run(...s));
    console.log('✅ 20 suppliers seeded');
  }

  console.log('✅ Database initialized');
}

function generatePONumber(db) {
  const prefix = db.prepare(`SELECT value FROM settings WHERE key = 'po_prefix'`).get()?.value || 'PO';
  const year = new Date().getFullYear();
  const count = db.prepare(`SELECT COUNT(*) as c FROM purchase_orders`).get().c + 1;
  return `${prefix}-${year}-${String(count).padStart(4, '0')}`;
}

module.exports = { db, initializeDatabase, generatePONumber };
