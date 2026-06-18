const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Helper: run a query
async function query(text, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    return res;
  } finally {
    client.release();
  }
}

// Synchronous-style wrapper used by server.js
// We expose a db object that mimics the better-sqlite3 API but uses async pg underneath
// server.js will be updated to use async/await

async function initializeDatabase() {
  await query(`
    CREATE TABLE IF NOT EXISTS buildings (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      address TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'gm')),
      building_id INTEGER REFERENCES buildings(id),
      active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS suppliers (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      contact_person TEXT,
      email TEXT,
      phone TEXT,
      category TEXT,
      address TEXT,
      notes TEXT,
      active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS categories (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      description TEXT
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS inventory_items (
      id SERIAL PRIMARY KEY,
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
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS purchase_orders (
      id SERIAL PRIMARY KEY,
      po_number TEXT NOT NULL UNIQUE,
      building_id INTEGER REFERENCES buildings(id),
      requested_by INTEGER REFERENCES users(id),
      supplier_id INTEGER REFERENCES suppliers(id),
      status TEXT DEFAULT 'pending',
      notes TEXT,
      quote_amount REAL,
      quote_notes TEXT,
      quoted_by INTEGER REFERENCES users(id),
      quoted_at TIMESTAMP,
      xero_invoice_id TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS po_items (
      id SERIAL PRIMARY KEY,
      po_id INTEGER NOT NULL REFERENCES purchase_orders(id) ON DELETE CASCADE,
      inventory_item_id INTEGER REFERENCES inventory_items(id),
      description TEXT NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      unit TEXT DEFAULT 'each',
      unit_price REAL,
      total_price REAL,
      category TEXT
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS xero_config (
      id INTEGER PRIMARY KEY,
      client_id TEXT,
      client_secret TEXT,
      tenant_id TEXT,
      access_token TEXT,
      refresh_token TEXT,
      token_expires_at TIMESTAMP
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS activity_log (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id INTEGER,
      details TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Seed categories
  const cats = ['Building & Maintenance','Equipment','Housekeeping & Cleaning','Linen & Bedding','Food & Beverage','Office Supplies','Guest Amenities','Safety & Security','IT & Technology','Other'];
  for (const c of cats) {
    await query(`INSERT INTO categories (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`, [c]);
  }

  // Seed default settings
  const defaults = [
    ['notification_email','finance@fluentliving.com'],
    ['company_name','Fluent Living'],
    ['po_prefix','FL-PO'],
    ['smtp_host',''],['smtp_port','587'],['smtp_user',''],['smtp_pass',''],['smtp_from','']
  ];
  for (const [k,v] of defaults) {
    await query(`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, [k, v]);
  }

  // Seed admin user
  const adminCheck = await query(`SELECT id FROM users WHERE role = 'admin' LIMIT 1`);
  if (adminCheck.rows.length === 0) {
    const hash = bcrypt.hashSync('Admin@2024!', 10);
    await query(`INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, 'admin')`,
      ['De-Mara', 'finance@fluentliving.com', hash]);
    console.log('✅ Admin user created: finance@fluentliving.com / Admin@2024!');
  }

  // Seed 20 suppliers
  const supCheck = await query(`SELECT COUNT(*) as c FROM suppliers`);
  if (parseInt(supCheck.rows[0].c) === 0) {
    const suppliers = [
      ['CleanPro Supplies','John Smith','orders@cleanpro.co.za','011 123 4567','Housekeeping & Cleaning'],
      ['Linen World','Sarah Jones','sarah@linenworld.co.za','021 456 7890','Linen & Bedding'],
      ['TechEquip SA','Mike Brown','mike@techequip.co.za','011 987 6543','IT & Technology'],
      ['Hospitality Depot','Lisa White','lisa@hospdepot.co.za','031 321 6540','Guest Amenities'],
      ['BuildRight SA','Tom Green','tom@buildright.co.za','011 555 4321','Building & Maintenance'],
      ['Office Essentials','Anna Blue','anna@officeessentials.co.za','021 789 0123','Office Supplies'],
      ['SafeGuard Solutions','Peter Black','peter@safeguard.co.za','011 222 3333','Safety & Security'],
      ['CaterSupply','Mary Pink','mary@cater.co.za','031 444 5555','Food & Beverage'],
      ['Ecolab SA','Chris Red','chris@ecolab.co.za','011 666 7777','Housekeeping & Cleaning'],
      ['Makro Business','David Grey','david@makro.co.za','012 888 9999','Office Supplies'],
      ['SA Hotel Supplies','Emma Purple','emma@sahotel.co.za','021 111 2222','Guest Amenities'],
      ['Steelcase Furniture','Frank Orange','frank@steelcase.co.za','011 333 4444','Equipment'],
      ['Plumbfix SA','Grace Yellow','grace@plumbfix.co.za','021 555 6666','Building & Maintenance'],
      ['ElectroSafe','Henry Teal','henry@electrosafe.co.za','011 777 8888','Building & Maintenance'],
      ['Medpet SA','Iris Cyan','iris@medpet.co.za','031 999 0000','Safety & Security'],
      ['Fresh & Clean','Jack Lime','jack@freshclean.co.za','011 000 1111','Housekeeping & Cleaning'],
      ['Premier Linens','Kate Navy','kate@premierlinens.co.za','021 222 3333','Linen & Bedding'],
      ['Smart Systems','Leo Maroon','leo@smartsystems.co.za','011 444 5555','IT & Technology'],
      ['Cape Catering Supplies','Mia Silver','mia@capecater.co.za','021 666 7777','Food & Beverage'],
      ['National Hygiene','Noah Gold','noah@nathygiene.co.za','011 888 9999','Housekeeping & Cleaning'],
    ];
    for (const s of suppliers) {
      await query(`INSERT INTO suppliers (name, contact_person, email, phone, category) VALUES ($1,$2,$3,$4,$5)`, s);
    }
    console.log('✅ 20 suppliers seeded');
  }

  console.log('✅ Database initialized');
}

async function generatePONumber() {
  const prefixRes = await query(`SELECT value FROM settings WHERE key = 'po_prefix'`);
  const prefix = prefixRes.rows[0]?.value || 'FL-PO';
  const year = new Date().getFullYear();
  const countRes = await query(`SELECT COUNT(*) as c FROM purchase_orders`);
  const count = parseInt(countRes.rows[0].c) + 1;
  return `${prefix}-${year}-${String(count).padStart(4, '0')}`;
}

module.exports = { query, initializeDatabase, generatePONumber };
