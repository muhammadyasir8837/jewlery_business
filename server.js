const express = require('express'), { DatabaseSync } = require('node:sqlite'),
  bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'change-this-secret';
const db = new DatabaseSync('store.db'); db.exec('PRAGMA foreign_keys = ON');
// simple transaction helper: all steps succeed together or none are saved
const tx = (fn) => { db.exec('BEGIN'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };

// ---------- DATABASE SCHEMA ----------
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'customer', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT NOT NULL, parent_id INTEGER);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, description TEXT, price REAL, stock INTEGER DEFAULT 0, image TEXT, category_id INTEGER REFERENCES categories(id), attributes TEXT DEFAULT '{}', active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, phone TEXT, address TEXT, payment TEXT, total REAL, status TEXT DEFAULT 'Pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), product_id INTEGER, name TEXT, price REAL, qty INTEGER);
CREATE TABLE IF NOT EXISTS coupons(id INTEGER PRIMARY KEY, code TEXT UNIQUE, percent REAL, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, name TEXT, email TEXT, message TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

// ---------- SEED DATA (runs once) ----------
if (!db.prepare('SELECT 1 FROM users').get()) {
  db.prepare('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)')
    .run('Admin', 'admin@store.com', bcrypt.hashSync('admin123', 10), 'admin');
  ['Jewellery', 'Earrings', 'Necklaces', 'Bracelets', 'Rings'].forEach((n, i) =>
    db.prepare('INSERT INTO categories(name,parent_id) VALUES(?,?)').run(n, i ? 1 : null));
  const items = [['Gold Hoop Earrings', 1200, 2], ['Pearl Drop Earrings', 950, 2], ['Layered Necklace', 2200, 3],
    ['Choker Set', 3100, 3], ['Charm Bracelet', 1500, 4], ['Rose Gold Ring', 800, 5], ['Stone Cocktail Ring', 1100, 5]];
  items.forEach(([n, p, c], i) => db.prepare('INSERT INTO products(name,description,price,stock,image,category_id,attributes) VALUES(?,?,?,?,?,?,?)')
    .run(n, 'Beautiful artificial jewellery piece.', p, 20, `https://picsum.photos/seed/jewel${i}/400/400`, c, JSON.stringify({ material: 'Alloy', finish: 'Gold plated' })));
}

// ---------- MIDDLEWARE ----------
const app = express(); app.use(express.json({ limit: '8mb' })); app.use(express.static('public'));
const getUser = (req) => { try { return jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); } catch { return null; } };
const auth = (req, res, next) => { req.user = getUser(req); req.user ? next() : res.status(401).json({ error: 'Please login' }); };
const admin = (req, res, next) => auth(req, res, () => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' }));
const token = (u) => ({ token: jwt.sign({ id: u.id, role: u.role, name: u.name }, SECRET, { expiresIn: '7d' }), name: u.name, role: u.role });

// ---------- AUTH ----------
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Fill all fields (password 6+ chars)' });
  try {
    const r = db.prepare('INSERT INTO users(name,email,password) VALUES(?,?,?)').run(name, email, bcrypt.hashSync(password, 10));
    res.json(token({ id: r.lastInsertRowid, role: 'customer', name }));
  } catch { res.status(400).json({ error: 'Email already used' }); }
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(req.body.email);
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password)) return res.status(401).json({ error: 'Wrong email or password' });
  res.json(token(u));
});

// ---------- PUBLIC SHOP API ----------
app.get('/api/categories', (_, res) => res.json(db.prepare('SELECT * FROM categories').all()));
app.get('/api/products', (req, res) => {
  const { category, q } = req.query;
  let sql = 'SELECT p.*, c.name category FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.active=1', a = [];
  if (category) { sql += ' AND (p.category_id=? OR c.parent_id=?)'; a.push(category, category); }
  if (q) { sql += ' AND p.name LIKE ?'; a.push(`%${q}%`); }
  res.json(db.prepare(sql + ' ORDER BY p.id DESC').all(...a));
});
app.post('/api/orders', auth, (req, res) => {
  const { name, phone, address, payment, items } = req.body;
  if (!name || !phone || !address || !items?.length) return res.status(400).json({ error: 'Fill all checkout fields' });
  try {
    const id = tx(() => {
      let total = 0; const lines = [];
      for (const it of items) {
        const p = db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(it.id);
        const qty = Math.max(1, parseInt(it.qty) || 1);
        if (!p || p.stock < qty) throw new Error(`${p ? p.name : 'Item'} is out of stock`);
        db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(qty, p.id);
        total += p.price * qty; lines.push([p, qty]); // price always taken from DB, never from browser
      }
      const code = (req.body.coupon || '').trim().toUpperCase();
      if (code) { const cp = db.prepare('SELECT percent FROM coupons WHERE code=? AND active=1').get(code); if (!cp) throw new Error('Invalid coupon'); total = Math.round(total * (1 - cp.percent / 100)); }
      const o = db.prepare('INSERT INTO orders(user_id,name,phone,address,payment,total) VALUES(?,?,?,?,?,?)').run(req.user.id, name, phone, address, payment || 'Cash on Delivery', total);
      lines.forEach(([p, q]) => db.prepare('INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES(?,?,?,?,?)').run(o.lastInsertRowid, p.id, p.name, p.price, q));
      return Number(o.lastInsertRowid);
    });
    res.json({ orderId: id });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/my-orders', auth, (req, res) => res.json(db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(req.user.id)));

// ---------- ADMIN API ----------
app.get('/api/admin/stats', admin, (_, res) => res.json({
  sales: db.prepare("SELECT COALESCE(SUM(total),0) v FROM orders WHERE status!='Cancelled'").get().v,
  orders: db.prepare('SELECT COUNT(*) v FROM orders').get().v,
  customers: db.prepare("SELECT COUNT(*) v FROM users WHERE role='customer'").get().v,
  lowStock: db.prepare('SELECT name,stock FROM products WHERE stock<=5 AND active=1').all(),
  byStatus: db.prepare('SELECT status, COUNT(*) n FROM orders GROUP BY status').all(),
  byDay: db.prepare("SELECT substr(created_at,1,10) d, SUM(total) v FROM orders WHERE status!='Cancelled' GROUP BY d ORDER BY d DESC LIMIT 7").all()
}));
app.get('/api/admin/products', admin, (_, res) => res.json(db.prepare('SELECT p.*, c.name category FROM products p LEFT JOIN categories c ON c.id=p.category_id ORDER BY p.id DESC').all()));
app.post('/api/admin/products', admin, (req, res) => {
  const b = req.body;
  const r = db.prepare('INSERT INTO products(name,description,price,stock,image,category_id,attributes) VALUES(?,?,?,?,?,?,?)')
    .run(b.name, b.description || '', +b.price, +b.stock, b.image, +b.category_id || null, b.attributes || '{}');
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/admin/products/:id', admin, (req, res) => {
  const b = req.body;
  db.prepare('UPDATE products SET name=?,description=?,price=?,stock=?,image=?,category_id=?,attributes=?,active=? WHERE id=?')
    .run(b.name, b.description, +b.price, +b.stock, b.image, +b.category_id || null, b.attributes || '{}', b.active ?? 1, req.params.id);
  res.json({ ok: true });
});
app.delete('/api/admin/products/:id', admin, (req, res) => {
  db.prepare('UPDATE products SET active=0 WHERE id=?').run(req.params.id); res.json({ ok: true }); // soft delete keeps order history safe
});
app.post('/api/admin/categories', admin, (req, res) => {
  db.prepare('INSERT INTO categories(name,parent_id) VALUES(?,?)').run(req.body.name, req.body.parent_id || null); res.json({ ok: true });
});
app.delete('/api/admin/categories/:id', admin, (req, res) => {
  if (db.prepare('SELECT 1 FROM products WHERE category_id=?').get(req.params.id)) return res.status(400).json({ error: 'Category has products' });
  db.prepare('DELETE FROM categories WHERE id=?').run(req.params.id); res.json({ ok: true });
});
app.get('/api/admin/orders', admin, (_, res) => {
  const orders = db.prepare('SELECT * FROM orders ORDER BY id DESC').all();
  orders.forEach(o => o.items = db.prepare('SELECT name,price,qty FROM order_items WHERE order_id=?').all(o.id));
  res.json(orders);
});
app.put('/api/admin/orders/:id', admin, (req, res) => {
  db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status, req.params.id); res.json({ ok: true });
});
app.get('/api/admin/customers', admin, (_, res) => res.json(db.prepare("SELECT id,name,email,created_at FROM users WHERE role='customer'").all()));

const fs = require('fs'); fs.mkdirSync('public/uploads', { recursive: true });
db.prepare("INSERT OR IGNORE INTO coupons(code,percent) VALUES('WELCOME10',10)").run();
app.post('/api/admin/upload', admin, (req, res) => {
  const m = /^data:image\/(png|jpeg|webp);base64,(.+)$/.exec(req.body.data || '');
  if (!m) return res.status(400).json({ error: 'Use a PNG, JPG or WEBP image' });
  const url = `/uploads/${Date.now()}.${m[1] === 'jpeg' ? 'jpg' : m[1]}`;
  fs.writeFileSync('public' + url, Buffer.from(m[2], 'base64')); res.json({ url });
});
app.get('/api/coupon/:code', (req, res) => {
  const c = db.prepare('SELECT code,percent FROM coupons WHERE code=? AND active=1').get(req.params.code.toUpperCase());
  c ? res.json(c) : res.status(404).json({ error: 'Invalid coupon' });
});
app.get('/api/admin/coupons', admin, (_, res) => res.json(db.prepare('SELECT * FROM coupons').all()));
app.post('/api/admin/coupons', admin, (req, res) => {
  try { db.prepare('INSERT INTO coupons(code,percent) VALUES(?,?)').run(String(req.body.code).trim().toUpperCase(), Math.min(90, Math.max(1, +req.body.percent || 0))); res.json({ ok: true }); }
  catch { res.status(400).json({ error: 'Code already exists' }); }
});
app.delete('/api/admin/coupons/:id', admin, (req, res) => { db.prepare('DELETE FROM coupons WHERE id=?').run(req.params.id); res.json({ ok: true }); });
app.post('/api/contact', (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) return res.status(400).json({ error: 'Fill all fields' });
  db.prepare('INSERT INTO messages(name,email,message) VALUES(?,?,?)').run(String(name).slice(0, 100), String(email).slice(0, 100), String(message).slice(0, 2000)); res.json({ ok: true });
});
app.get('/api/admin/messages', admin, (_, res) => res.json(db.prepare('SELECT * FROM messages ORDER BY id DESC').all()));

app.listen(3000, () => console.log('Store running: http://localhost:3000   Admin: http://localhost:3000/admin.html'));
