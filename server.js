const express = require('express');
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs'); // Add bcrypt for password hashing

const app = express();
const PORT = process.env.PORT || 3001;

// Database path
const DB_PATH = path.join(__dirname, 'data', 'finance.db');

// Ensure data directory exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}

let db;

// Initialize database
async function initDatabase() {
  const SQL = await initSqlJs();

  // Load existing database or create new one
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  // Create tables for multi-tenant architecture
  // Superadmin table - Technical Support and Technical Owner
  db.run(`
    CREATE TABLE IF NOT EXISTS superadmin (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Families table - Each tenant
  db.run(`
    CREATE TABLE IF NOT EXISTS families (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_active INTEGER DEFAULT 1
    )
  `);

  // Users table - Family admins and members
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      family_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      email TEXT,
      password_hash TEXT,
      avatar TEXT DEFAULT '👤',
      role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('admin', 'member')),
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (family_id) REFERENCES families(id)
    )
  `);

  // Categories table - now with family_id
  db.run(`
    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      family_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
      icon TEXT DEFAULT '📁',
      color TEXT DEFAULT '#14b8a6',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (family_id) REFERENCES families(id)
    )
  `);

  // Transactions table - now with family_id and user_id
  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      family_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      category_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
      amount REAL NOT NULL,
      description TEXT,
      date DATE NOT NULL,
      is_recurring INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (family_id) REFERENCES families(id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (category_id) REFERENCES categories(id)
    )
  `);

  // Budgets table - now with family_id
  db.run(`
    CREATE TABLE IF NOT EXISTS budgets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      family_id INTEGER NOT NULL,
      category_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      month INTEGER NOT NULL,
      year INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (family_id) REFERENCES families(id),
      FOREIGN KEY (category_id) REFERENCES categories(id),
      UNIQUE(family_id, category_id, month, year)
    )
  `);

  // Seed default superadmin if empty
  const superadminResult = db.exec('SELECT COUNT(*) as count FROM superadmin');
  const superadminCount = superadminResult[0]?.values[0][0] || 0;

  if (superadminCount === 0) {
    const defaultPassword = 'superadmin123'; // Default password for superadmin
    const passwordHash = await bcrypt.hash(defaultPassword, 10);
    db.run("INSERT INTO superadmin (username, password_hash, email, name) VALUES ('superadmin', ?, 'support@familyfinance.com', 'Technical Support')", [passwordHash]);
    console.log('✅ Superadmin created with default password: superadmin123');
  }

  // Seed default family if empty
  const familyResult = db.exec('SELECT COUNT(*) as count FROM families');
  const familyCount = familyResult[0]?.values[0][0] || 0;

  if (familyCount === 0) {
    db.run("INSERT INTO families (name) VALUES ('Keluarga Anda')");
    const familyId = db.exec('SELECT last_insert_rowid() as id')[0]?.values[0][0];

    // Create default admin user for the family
    const defaultUserPassword = 'admin123';
    const userPasswordHash = await bcrypt.hash(defaultUserPassword, 10);
    db.run("INSERT INTO users (family_id, name, email, password_hash, avatar, role) VALUES (?, 'Admin', 'admin@family.com', ?, '👨‍👩‍👧‍👦', 'admin')", [familyId, userPasswordHash]);

    // Create default categories for the family
    const categories = [
      // Expense categories
      ['Makan', 'expense', '🍔', '#f43f5e'],
      ['Transport', 'expense', '🚗', '#f59e0b'],
      ['Belanja', 'expense', '🛒', '#8b5cf6'],
      ['Pendidikan', 'expense', '🎓', '#3b82f6'],
      ['Kesehatan', 'expense', '💊', '#10b981'],
      ['Hiburan', 'expense', '🎮', '#ec4899'],
      ['Tagihan', 'expense', '📄', '#6366f1'],
      ['Lainnya', 'expense', '📦', '#64748b'],
      // Income categories
      ['Gaji', 'income', '💰', '#10b981'],
      ['Usaha', 'income', '🏪', '#14b8a6'],
      ['Investasi', 'income', '📈', '#22c55e'],
      ['Bonus', 'income', '🎁', '#84cc16']
    ];

    for (const [name, type, icon, color] of categories) {
      db.run("INSERT INTO categories (family_id, name, type, icon, color) VALUES (?, ?, ?, ?, ?)", [familyId, name, type, icon, color]);
    }

    console.log('✅ Default family created with admin user and categories');
  }

  saveDatabase();
  console.log('✅ Multi-tenant database initialized');
}

// Save database to file
function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Helper function to run query and return results as objects
function query(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    if (params.length > 0) {
      stmt.bind(params);
    }

    const results = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push(row);
    }
    stmt.free();
    return results;
  } catch (err) {
    console.error('Query error:', err);
    return [];
  }
}

// Helper function to run insert/update
function run(sql, params = []) {
  try {
    db.run(sql, params);
    saveDatabase();
    return { lastId: db.exec('SELECT last_insert_rowid()')[0]?.values[0][0] };
  } catch (err) {
    console.error('Run error:', err);
    return { error: err.message };
  }
}

// Authentication middleware
function authenticateUser(req, res, next) {
  const { familyId, userId } = req.session || {};
  const { superadminId } = req.session || {}; // Also check for superadmin session

  // If user is a superadmin, allow access but set context appropriately
  if (superadminId) {
    // Verify superadmin exists
    const superadmin = query('SELECT * FROM superadmin WHERE id = ?', [superadminId]);
    if (superadmin.length === 0) {
      return res.status(401).json({ error: 'Unauthorized: Invalid superadmin session' });
    }

    // For superadmin accessing family endpoints, we need familyId from request
    const requestedFamilyId = req.body.family_id || req.query.familyId || familyId;

    if (!requestedFamilyId) {
      return res.status(400).json({ error: 'Family ID is required for superadmin access' });
    }

    // Verify family exists
    const family = query('SELECT * FROM families WHERE id = ? AND is_active = 1', [requestedFamilyId]);
    if (family.length === 0) {
      return res.status(404).json({ error: 'Family not found' });
    }

    // Create a temporary user context for the superadmin
    req.user = {
      id: 0, // Superadmin doesn't have a specific user ID for the family
      family_id: requestedFamilyId,
      role: 'admin', // Give superadmin admin privileges for the family context
      name: superadmin[0].name
    };

    req.superadmin = superadmin[0];
    next();
    return;
  }

  // Regular user authentication
  if (!familyId || !userId) {
    return res.status(401).json({ error: 'Unauthorized: Please log in' });
  }

  // Verify user exists and is active in the specified family
  const user = query('SELECT * FROM users WHERE id = ? AND family_id = ? AND is_active = 1', [userId, familyId]);

  if (user.length === 0) {
    return res.status(401).json({ error: 'Unauthorized: Invalid session' });
  }

  req.user = user[0];
  next();
}

// Superadmin authentication middleware
function authenticateSuperadmin(req, res, next) {
  const { superadminId } = req.session || {};

  if (!superadminId) {
    return res.status(401).json({ error: 'Unauthorized: Superadmin access required' });
  }

  // Verify superadmin exists
  const superadmin = query('SELECT * FROM superadmin WHERE id = ?', [superadminId]);

  if (superadmin.length === 0) {
    return res.status(401).json({ error: 'Unauthorized: Invalid superadmin session' });
  }

  req.superadmin = superadmin[0];
  next();
}

// Session management (in-memory for this example)
const sessions = new Map();

// Simple session middleware
app.use((req, res, next) => {
  // Get session ID from header or cookie
  const sessionId = req.headers['x-session-id'] || req.query.sessionId;

  if (sessionId && sessions.has(sessionId)) {
    req.session = sessions.get(sessionId);
  } else {
    req.session = {};
  }

  // Add method to create session
  req.createSession = (data) => {
    const newSessionId = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    sessions.set(newSessionId, data);
    return newSessionId;
  };

  next();
});

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============ AUTHENTICATION API ============

// Superadmin login
app.post('/api/auth/superadmin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const superadmin = query('SELECT * FROM superadmin WHERE username = ?', [username]);

  if (superadmin.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const isValid = await bcrypt.compare(password, superadmin[0].password_hash);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const sessionId = req.createSession({
    superadminId: superadmin[0].id
  });

  res.json({
    success: true,
    sessionId,
    user: {
      id: superadmin[0].id,
      name: superadmin[0].name,
      email: superadmin[0].email,
      role: 'superadmin'
    }
  });
});

// Family member login
app.post('/api/auth/family/login', async (req, res) => {
  const { email, password, familyId } = req.body;

  if (!email || !password || !familyId) {
    return res.status(400).json({ error: 'Email, password, and family ID are required' });
  }

  const user = query('SELECT * FROM users WHERE email = ? AND family_id = ? AND is_active = 1', [email, familyId]);

  if (user.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials or family' });
  }

  const isValid = await bcrypt.compare(password, user[0].password_hash);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const sessionId = req.createSession({
    familyId: user[0].family_id,
    userId: user[0].id
  });

  res.json({
    success: true,
    sessionId,
    user: {
      id: user[0].id,
      name: user[0].name,
      email: user[0].email,
      role: user[0].role,
      familyId: user[0].family_id,
      avatar: user[0].avatar
    }
  });
});

// ============ SUPERADMIN API ROUTES ============

// Get all families (Superadmin only)
app.get('/api/superadmin/families', authenticateSuperadmin, (req, res) => {
  const families = query(`
    SELECT f.*,
           (SELECT COUNT(*) FROM users WHERE family_id = f.id AND is_active = 1) as member_count
    FROM families f
    WHERE f.is_active = 1
    ORDER BY f.created_at DESC
  `);
  res.json(families);
});

// Create new family (Superadmin only)
app.post('/api/superadmin/families', authenticateSuperadmin, async (req, res) => {
  const { name, members } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Family name is required' });
  }

  const result = run('INSERT INTO families (name) VALUES (?)', [name]);

  if (result.error) {
    return res.status(500).json({ error: result.error });
  }

  // Create family members if provided
  if (members && Array.isArray(members) && members.length > 0) {
    // Limit to 3 members maximum
    const maxMembers = 3;
    let processedCount = 0;
    let hasAdmin = false;

    for (const member of members) {
      if (processedCount >= maxMembers) break;

      const { name: memberName, email, avatar, role = 'member' } = member;
      const defaultPassword = role === 'admin' ? 'admin123' : 'member123';
      const passwordHash = await bcrypt.hash(defaultPassword, 10);

      run(
        'INSERT INTO users (family_id, name, email, password_hash, avatar, role) VALUES (?, ?, ?, ?, ?, ?)',
        [result.lastId, memberName, email || '', passwordHash, avatar || '👤', role]
      );

      if (role === 'admin') hasAdmin = true;
      processedCount++;
    }

    // If no admin was provided and we have space, create a default admin
    if (!hasAdmin && processedCount < maxMembers) {
      const defaultPassword = 'admin123';
      const passwordHash = await bcrypt.hash(defaultPassword, 10);
      run(
        'INSERT INTO users (family_id, name, email, password_hash, avatar, role) VALUES (?, ?, ?, ?, ?, ?)',
        [result.lastId, 'Admin', `admin@family${result.lastId}.com`, passwordHash, '👨‍👩‍👧‍👦', 'admin']
      );
      processedCount++;
    }
  } else {
    // Create default admin user for the new family if no members provided
    const defaultPassword = 'admin123';
    const passwordHash = bcrypt.hashSync(defaultPassword, 10);
    run(
      'INSERT INTO users (family_id, name, email, password_hash, avatar, role) VALUES (?, ?, ?, ?, ?, ?)',
      [result.lastId, 'Admin', `admin@family${result.lastId}.com`, passwordHash, '👨‍👩‍👧‍👦', 'admin']
    );
  }

  const family = query('SELECT * FROM families WHERE id = ?', [result.lastId]);
  const createdMembers = query('SELECT id, name, email, avatar, role FROM users WHERE family_id = ?', [result.lastId]);

  res.json({
    id: result.lastId,
    ...family[0],
    members: createdMembers
  });
});

// Update family (Superadmin only)
app.put('/api/superadmin/families/:id', authenticateSuperadmin, (req, res) => {
  const { name } = req.body;
  const familyId = parseInt(req.params.id);

  run('UPDATE families SET name = ? WHERE id = ?', [name, familyId]);
  res.json({ id: familyId, name });
});

// Delete family (Superadmin only)
app.delete('/api/superadmin/families/:id', authenticateSuperadmin, (req, res) => {
  const familyId = parseInt(req.params.id);

  // Soft delete family
  run('UPDATE families SET is_active = 0 WHERE id = ?', [familyId]);
  res.json({ success: true });
});

// Get all users in a family (Superadmin only)
app.get('/api/superadmin/families/:id/users', authenticateSuperadmin, (req, res) => {
  const familyId = parseInt(req.params.id);
  const users = query('SELECT id, name, email, avatar, role, is_active FROM users WHERE family_id = ? ORDER BY role DESC, name', [familyId]);
  res.json(users);
});

// ============ SUPERADMIN FINANCIAL MODULES ============

// Get all transactions across all families (Superadmin only)
app.get('/api/superadmin/transactions', authenticateSuperadmin, (req, res) => {
  const { familyId, month, year, type, category_id } = req.query;

  let sql = `
    SELECT t.*, c.name as category_name, c.icon as category_icon, c.color as category_color,
           u.name as user_name, f.name as family_name
    FROM transactions t
    JOIN categories c ON t.category_id = c.id
    JOIN users u ON t.user_id = u.id
    JOIN families f ON t.family_id = f.id
  `;
  const params = [];

  if (familyId) {
    sql += ` WHERE t.family_id = ?`;
    params.push(parseInt(familyId));
  } else {
    sql += ` WHERE 1=1`; // Placeholder condition
  }

  if (month && year) {
    const monthStr = String(month).padStart(2, '0');
    sql += ` AND strftime('%m', t.date) = ? AND strftime('%Y', t.date) = ?`;
    params.push(monthStr, String(year));
  }
  if (type) {
    sql += ` AND t.type = ?`;
    params.push(type);
  }
  if (category_id) {
    sql += ` AND t.category_id = ?`;
    params.push(parseInt(category_id));
  }

  sql += ' ORDER BY t.date DESC, t.id DESC';

  const transactions = query(sql, params);
  res.json(transactions);
});

// Create transaction for any family (Superadmin only)
app.post('/api/superadmin/transactions', authenticateSuperadmin, (req, res) => {
  const { family_id, user_id, category_id, type, amount, description, date, is_recurring } = req.body;

  // Verify family and user exist
  const family = query('SELECT * FROM families WHERE id = ?', [family_id]);
  if (family.length === 0) {
    return res.status(404).json({ error: 'Family not found' });
  }

  const user = query('SELECT * FROM users WHERE id = ? AND family_id = ?', [user_id, family_id]);
  if (user.length === 0) {
    return res.status(404).json({ error: 'User not found in specified family' });
  }

  const result = run(
    'INSERT INTO transactions (family_id, user_id, category_id, type, amount, description, date, is_recurring) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [family_id, user_id, category_id, type, amount, description || '', date, is_recurring ? 1 : 0]
  );

  if (result.error) {
    return res.status(500).json({ error: result.error });
  }

  const transaction = query(`
    SELECT t.*, c.name as category_name, c.icon as category_icon, c.color as category_color,
           u.name as user_name, f.name as family_name
    FROM transactions t
    JOIN categories c ON t.category_id = c.id
    JOIN users u ON t.user_id = u.id
    JOIN families f ON t.family_id = f.id
    WHERE t.id = ?
  `, [result.lastId]);

  res.json(transaction[0]);
});

// Update transaction for any family (Superadmin only)
app.put('/api/superadmin/transactions/:id', authenticateSuperadmin, (req, res) => {
  const { family_id, user_id, category_id, type, amount, description, date, is_recurring } = req.body;
  const transactionId = parseInt(req.params.id);

  // Verify transaction exists and belongs to the specified family
  const transaction = query('SELECT * FROM transactions WHERE id = ? AND family_id = ?', [transactionId, family_id]);
  if (transaction.length === 0) {
    return res.status(404).json({ error: 'Transaction not found in specified family' });
  }

  run(
    'UPDATE transactions SET category_id = ?, type = ?, amount = ?, description = ?, date = ?, is_recurring = ? WHERE id = ? AND family_id = ?',
    [category_id, type, amount, description || '', date, is_recurring ? 1 : 0, transactionId, family_id]
  );

  const updatedTransaction = query(`
    SELECT t.*, c.name as category_name, c.icon as category_icon, c.color as category_color,
           u.name as user_name, f.name as family_name
    FROM transactions t
    JOIN categories c ON t.category_id = c.id
    JOIN users u ON t.user_id = u.id
    JOIN families f ON t.family_id = f.id
    WHERE t.id = ?
  `, [transactionId]);

  res.json(updatedTransaction[0]);
});

// Delete transaction for any family (Superadmin only)
app.delete('/api/superadmin/transactions/:id', authenticateSuperadmin, (req, res) => {
  const transactionId = parseInt(req.params.id);
  const { family_id } = req.body; // Family ID is passed in the request body for verification

  // Verify transaction exists and belongs to the specified family
  const transaction = query('SELECT * FROM transactions WHERE id = ? AND family_id = ?', [transactionId, family_id]);
  if (transaction.length === 0) {
    return res.status(404).json({ error: 'Transaction not found in specified family' });
  }

  run('DELETE FROM transactions WHERE id = ? AND family_id = ?', [transactionId, family_id]);
  res.json({ success: true });
});

// Get all budgets across all families (Superadmin only)
app.get('/api/superadmin/budgets', authenticateSuperadmin, (req, res) => {
  const { familyId, month, year } = req.query;

  let sql = `
    SELECT b.*, c.name as category_name, c.icon as category_icon, c.color as category_color,
           f.name as family_name
    FROM budgets b
    JOIN categories c ON b.category_id = c.id
    JOIN families f ON b.family_id = f.id
  `;
  const params = [];

  if (familyId) {
    sql += ` WHERE b.family_id = ?`;
    params.push(parseInt(familyId));
  } else {
    sql += ` WHERE 1=1`; // Placeholder condition
  }

  if (month && year) {
    sql += ` AND b.month = ? AND b.year = ?`;
    params.push(parseInt(month), parseInt(year));
  }

  sql += ' ORDER BY f.name, b.month, b.year';

  const budgets = query(sql, params);
  res.json(budgets);
});

// Create or update budget for any family (Superadmin only)
app.post('/api/superadmin/budgets', authenticateSuperadmin, (req, res) => {
  const { family_id, category_id, amount, month, year } = req.body;

  // Verify family and category exist
  const family = query('SELECT * FROM families WHERE id = ?', [family_id]);
  if (family.length === 0) {
    return res.status(404).json({ error: 'Family not found' });
  }

  const category = query('SELECT * FROM categories WHERE id = ? AND family_id = ?', [category_id, family_id]);
  if (category.length === 0) {
    return res.status(404).json({ error: 'Category not found in specified family' });
  }

  // Check if budget exists
  const existing = query(
    'SELECT id FROM budgets WHERE family_id = ? AND category_id = ? AND month = ? AND year = ?',
    [family_id, category_id, month, year]
  );

  if (existing.length > 0) {
    run('UPDATE budgets SET amount = ? WHERE id = ? AND family_id = ?', [amount, existing[0].id, family_id]);
    const updatedBudget = query(`
      SELECT b.*, c.name as category_name, c.icon as category_icon, c.color as category_color,
             f.name as family_name
      FROM budgets b
      JOIN categories c ON b.category_id = c.id
      JOIN families f ON b.family_id = f.id
      WHERE b.id = ?
    `, [existing[0].id]);
    res.json(updatedBudget[0]);
  } else {
    const result = run(
      'INSERT INTO budgets (family_id, category_id, amount, month, year) VALUES (?, ?, ?, ?, ?)',
      [family_id, category_id, amount, month, year]
    );

    if (result.error) {
      return res.status(500).json({ error: result.error });
    }

    const newBudget = query(`
      SELECT b.*, c.name as category_name, c.icon as category_icon, c.color as category_color,
             f.name as family_name
      FROM budgets b
      JOIN categories c ON b.category_id = c.id
      JOIN families f ON b.family_id = f.id
      WHERE b.id = ?
    `, [result.lastId]);

    res.json(newBudget[0]);
  }
});

// Get all categories across all families (Superadmin only)
app.get('/api/superadmin/categories', authenticateSuperadmin, (req, res) => {
  const { familyId } = req.query;

  let sql = `
    SELECT c.*, f.name as family_name
    FROM categories c
    JOIN families f ON c.family_id = f.id
  `;
  const params = [];

  if (familyId) {
    sql += ` WHERE c.family_id = ?`;
    params.push(parseInt(familyId));
  } else {
    sql += ` WHERE 1=1`; // Placeholder condition
  }

  sql += ' ORDER BY f.name, c.type, c.name';

  const categories = query(sql, params);
  res.json(categories);
});

// Create category for any family (Superadmin only)
app.post('/api/superadmin/categories', authenticateSuperadmin, (req, res) => {
  const { family_id, name, type, icon, color } = req.body;

  // Verify family exists
  const family = query('SELECT * FROM families WHERE id = ?', [family_id]);
  if (family.length === 0) {
    return res.status(404).json({ error: 'Family not found' });
  }

  const result = run(
    'INSERT INTO categories (family_id, name, type, icon, color) VALUES (?, ?, ?, ?, ?)',
    [family_id, name, type, icon || '📁', color || '#14b8a6']
  );

  if (result.error) {
    return res.status(500).json({ error: result.error });
  }

  const category = query(`
    SELECT c.*, f.name as family_name
    FROM categories c
    JOIN families f ON c.family_id = f.id
    WHERE c.id = ?
  `, [result.lastId]);

  res.json(category[0]);
});

// Update category for any family (Superadmin only)
app.put('/api/superadmin/categories/:id', authenticateSuperadmin, (req, res) => {
  const { family_id, name, type, icon, color } = req.body;
  const categoryId = parseInt(req.params.id);

  // Verify category exists and belongs to the specified family
  const category = query('SELECT * FROM categories WHERE id = ? AND family_id = ?', [categoryId, family_id]);
  if (category.length === 0) {
    return res.status(404).json({ error: 'Category not found in specified family' });
  }

  run(
    'UPDATE categories SET name = ?, type = ?, icon = ?, color = ? WHERE id = ? AND family_id = ?',
    [name, type, icon, color, categoryId, family_id]
  );

  const updatedCategory = query(`
    SELECT c.*, f.name as family_name
    FROM categories c
    JOIN families f ON c.family_id = f.id
    WHERE c.id = ?
  `, [categoryId]);

  res.json(updatedCategory[0]);
});

// Delete category for any family (Superadmin only)
app.delete('/api/superadmin/categories/:id', authenticateSuperadmin, (req, res) => {
  const categoryId = parseInt(req.params.id);
  const { family_id } = req.body; // Family ID is passed in the request body for verification

  // Verify category exists and belongs to the specified family
  const category = query('SELECT * FROM categories WHERE id = ? AND family_id = ?', [categoryId, family_id]);
  if (category.length === 0) {
    return res.status(404).json({ error: 'Category not found in specified family' });
  }

  // Check if category has associated transactions
  const transactions = query('SELECT COUNT(*) as count FROM transactions WHERE category_id = ?', [categoryId]);
  if (transactions[0]?.count > 0) {
    return res.status(400).json({ error: 'Cannot delete category with associated transactions' });
  }

  run('DELETE FROM categories WHERE id = ? AND family_id = ?', [categoryId, family_id]);
  res.json({ success: true });
});

// ============ FAMILY API ROUTES ============

// Categories (Family user authenticated)
app.get('/api/categories', authenticateUser, (req, res) => {
  const categories = query('SELECT * FROM categories WHERE family_id = ? ORDER BY type, name', [req.user.family_id]);
  res.json(categories);
});

app.post('/api/categories', authenticateUser, (req, res) => {
  const { name, type, icon, color } = req.body;

  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can create categories for any family
    const { family_id } = req.body;
    if (!family_id) {
      return res.status(400).json({ error: 'Family ID is required for superadmin category creation' });
    }

    // Verify family exists
    const family = query('SELECT * FROM families WHERE id = ?', [family_id]);
    if (family.length === 0) {
      return res.status(404).json({ error: 'Family not found' });
    }

    const result = run(
      'INSERT INTO categories (family_id, name, type, icon, color) VALUES (?, ?, ?, ?, ?)',
      [family_id, name, type, icon || '📁', color || '#14b8a6']
    );
    res.json({ id: result.lastId, name, type, icon, color, family_id });
  } else {
    // Regular user
    const result = run(
      'INSERT INTO categories (family_id, name, type, icon, color) VALUES (?, ?, ?, ?, ?)',
      [req.user.family_id, name, type, icon || '📁', color || '#14b8a6']
    );
    res.json({ id: result.lastId, name, type, icon, color });
  }
});

// Transactions (Family user authenticated)
app.get('/api/transactions', authenticateUser, (req, res) => {
  const { month, year, type, category_id } = req.query;

  let sql = `
    SELECT t.*, c.name as category_name, c.icon as category_icon, c.color as category_color, u.name as user_name
    FROM transactions t
    JOIN categories c ON t.category_id = c.id
    JOIN users u ON t.user_id = u.id
    WHERE t.family_id = ?
  `;
  const params = [req.user.family_id];

  if (month && year) {
    const monthStr = String(month).padStart(2, '0');
    sql += ` AND strftime('%m', t.date) = ? AND strftime('%Y', t.date) = ?`;
    params.push(monthStr, String(year));
  }
  if (type) {
    sql += ` AND t.type = ?`;
    params.push(type);
  }
  if (category_id) {
    sql += ` AND t.category_id = ?`;
    params.push(parseInt(category_id));
  }

  sql += ' ORDER BY t.date DESC, t.id DESC';

  const transactions = query(sql, params);
  res.json(transactions);
});

app.post('/api/transactions', authenticateUser, (req, res) => {
  const { category_id, type, amount, description, date, is_recurring, user_id } = req.body;

  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can create transactions for any family
    const { family_id } = req.body;
    if (!family_id) {
      return res.status(400).json({ error: 'Family ID is required for superadmin transaction creation' });
    }

    // Verify family and user exist
    const family = query('SELECT * FROM families WHERE id = ?', [family_id]);
    if (family.length === 0) {
      return res.status(404).json({ error: 'Family not found' });
    }

    const selected_user_id = user_id || req.user.id; // Use provided user_id or default to superadmin's context user
    const user = query('SELECT * FROM users WHERE id = ? AND family_id = ?', [selected_user_id, family_id]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found in specified family' });
    }

    const result = run(
      'INSERT INTO transactions (family_id, user_id, category_id, type, amount, description, date, is_recurring) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [family_id, selected_user_id, category_id, type, amount, description || '', date, is_recurring ? 1 : 0]
    );
    res.json({ id: result.lastId, ...req.body, family_id, user_id: selected_user_id });
  } else {
    // Regular user
    const result = run(
      'INSERT INTO transactions (family_id, user_id, category_id, type, amount, description, date, is_recurring) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [req.user.family_id, req.user.id, category_id, type, amount, description || '', date, is_recurring ? 1 : 0]
    );
    res.json({ id: result.lastId, ...req.body });
  }
});

app.put('/api/transactions/:id', authenticateUser, (req, res) => {
  const { category_id, type, amount, description, date, is_recurring, user_id } = req.body;
  const transactionId = parseInt(req.params.id);

  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can update transactions for any family
    const { family_id } = req.body;
    if (!family_id) {
      return res.status(400).json({ error: 'Family ID is required for superadmin transaction update' });
    }

    // Verify transaction belongs to specified family
    const transaction = query('SELECT * FROM transactions WHERE id = ? AND family_id = ?', [transactionId, family_id]);
    if (transaction.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Transaction does not belong to specified family' });
    }

    const selected_user_id = user_id || req.user.id; // Use provided user_id or default to superadmin's context user
    const user = query('SELECT * FROM users WHERE id = ? AND family_id = ?', [selected_user_id, family_id]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found in specified family' });
    }

    run(
      'UPDATE transactions SET category_id = ?, type = ?, amount = ?, description = ?, date = ?, is_recurring = ?, user_id = ? WHERE id = ? AND family_id = ?',
      [category_id, type, amount, description || '', date, is_recurring ? 1 : 0, selected_user_id, transactionId, family_id]
    );
    res.json({ id: transactionId, ...req.body, family_id, user_id: selected_user_id });
  } else {
    // Regular user - verify transaction belongs to user's family
    const transaction = query('SELECT * FROM transactions WHERE id = ? AND family_id = ?', [transactionId, req.user.family_id]);
    if (transaction.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Transaction does not belong to your family' });
    }

    run(
      'UPDATE transactions SET category_id = ?, type = ?, amount = ?, description = ?, date = ?, is_recurring = ? WHERE id = ? AND family_id = ?',
      [category_id, type, amount, description || '', date, is_recurring ? 1 : 0, transactionId, req.user.family_id]
    );
    res.json({ id: transactionId, ...req.body });
  }
});

app.delete('/api/transactions/:id', authenticateUser, (req, res) => {
  const transactionId = parseInt(req.params.id);

  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can delete transactions for any family
    const { family_id } = req.body;
    if (!family_id) {
      return res.status(400).json({ error: 'Family ID is required for superadmin transaction deletion' });
    }

    // Verify transaction belongs to specified family
    const transaction = query('SELECT * FROM transactions WHERE id = ? AND family_id = ?', [transactionId, family_id]);
    if (transaction.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Transaction does not belong to specified family' });
    }

    run('DELETE FROM transactions WHERE id = ? AND family_id = ?', [transactionId, family_id]);
    res.json({ success: true });
  } else {
    // Regular user - verify transaction belongs to user's family
    const transaction = query('SELECT * FROM transactions WHERE id = ? AND family_id = ?', [transactionId, req.user.family_id]);
    if (transaction.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Transaction does not belong to your family' });
    }

    run('DELETE FROM transactions WHERE id = ? AND family_id = ?', [transactionId, req.user.family_id]);
    res.json({ success: true });
  }
});

// Budgets (Family user authenticated)
app.get('/api/budgets', authenticateUser, (req, res) => {
  const { month, year } = req.query;
  const currentMonth = parseInt(month) || new Date().getMonth() + 1;
  const currentYear = parseInt(year) || new Date().getFullYear();
  const monthStr = String(currentMonth).padStart(2, '0');
  const yearStr = String(currentYear);

  // Check if this is a superadmin request with family context
  const familyId = req.superadmin ? (req.query.familyId ? parseInt(req.query.familyId) : req.user.family_id) : req.user.family_id;

  // First get budgets for the period
  const budgets = query(
    `SELECT b.*, c.name as category_name, c.icon as category_icon, c.color as category_color
     FROM budgets b
     JOIN categories c ON b.category_id = c.id
     WHERE b.family_id = ? AND b.month = ? AND b.year = ?`,
    [familyId, currentMonth, currentYear]
  );

  // Then get spent amounts for each budget
  budgets.forEach(budget => {
    const spentResult = query(
      `SELECT COALESCE(SUM(amount), 0) as spent FROM transactions
       WHERE family_id = ? AND category_id = ? AND strftime('%m', date) = ? AND strftime('%Y', date) = ? AND type = 'expense'`,
      [familyId, budget.category_id, monthStr, yearStr]
    );
    budget.spent = spentResult[0]?.spent || 0;
  });

  res.json(budgets);
});

app.post('/api/budgets', authenticateUser, (req, res) => {
  const { category_id, amount, month, year } = req.body;

  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can create budgets for any family
    const { family_id } = req.body;
    if (!family_id) {
      return res.status(400).json({ error: 'Family ID is required for superadmin budget creation' });
    }

    // Verify category belongs to specified family
    const category = query('SELECT * FROM categories WHERE id = ? AND family_id = ?', [category_id, family_id]);
    if (category.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Category does not belong to specified family' });
    }

    // Check if budget exists
    const existing = query(
      'SELECT id FROM budgets WHERE family_id = ? AND category_id = ? AND month = ? AND year = ?',
      [family_id, category_id, month, year]
    );

    if (existing.length > 0) {
      run('UPDATE budgets SET amount = ? WHERE id = ? AND family_id = ?', [amount, existing[0].id, family_id]);
      res.json({ id: existing[0].id, ...req.body, family_id });
    } else {
      const result = run(
        'INSERT INTO budgets (family_id, category_id, amount, month, year) VALUES (?, ?, ?, ?, ?)',
        [family_id, category_id, amount, month, year]
      );
      res.json({ id: result.lastId, ...req.body, family_id });
    }
  } else {
    // Regular user - verify category belongs to user's family
    const category = query('SELECT * FROM categories WHERE id = ? AND family_id = ?', [category_id, req.user.family_id]);
    if (category.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Category does not belong to your family' });
    }

    // Check if budget exists
    const existing = query(
      'SELECT id FROM budgets WHERE family_id = ? AND category_id = ? AND month = ? AND year = ?',
      [req.user.family_id, category_id, month, year]
    );

    if (existing.length > 0) {
      run('UPDATE budgets SET amount = ? WHERE id = ? AND family_id = ?', [amount, existing[0].id, req.user.family_id]);
      res.json({ id: existing[0].id, ...req.body });
    } else {
      const result = run(
        'INSERT INTO budgets (family_id, category_id, amount, month, year) VALUES (?, ?, ?, ?, ?)',
        [req.user.family_id, category_id, amount, month, year]
      );
      res.json({ id: result.lastId, ...req.body });
    }
  }
});

// Dashboard Summary (Family user authenticated)
app.get('/api/dashboard', authenticateUser, (req, res) => {
  const { month, year } = req.query;
  const currentMonth = parseInt(month) || new Date().getMonth() + 1;
  const currentYear = parseInt(year) || new Date().getFullYear();
  const monthStr = String(currentMonth).padStart(2, '0');
  const yearStr = String(currentYear);

  // Check if this is a superadmin request with family context
  const familyId = req.superadmin ? (req.query.familyId ? parseInt(req.query.familyId) : req.user.family_id) : req.user.family_id;

  // Total income
  const incomeResult = query(
    `SELECT COALESCE(SUM(amount), 0) as total FROM transactions
     WHERE family_id = ? AND type = 'income' AND strftime('%m', date) = ? AND strftime('%Y', date) = ?`,
    [familyId, monthStr, yearStr]
  );
  const income = incomeResult[0]?.total || 0;

  // Total expense
  const expenseResult = query(
    `SELECT COALESCE(SUM(amount), 0) as total FROM transactions
     WHERE family_id = ? AND type = 'expense' AND strftime('%m', date) = ? AND strftime('%Y', date) = ?`,
    [familyId, monthStr, yearStr]
  );
  const expense = expenseResult[0]?.total || 0;

  // Expenses by category
  const expensesByCategory = query(
    `SELECT c.id, c.name, c.icon, c.color, COALESCE(SUM(t.amount), 0) as total
     FROM categories c
     LEFT JOIN transactions t ON c.id = t.category_id AND t.family_id = ?
       AND strftime('%m', t.date) = ? AND strftime('%Y', t.date) = ?
       AND t.type = 'expense'
     WHERE c.family_id = ? AND c.type = 'expense'
     GROUP BY c.id
     HAVING total > 0
     ORDER BY total DESC`,
    [familyId, monthStr, yearStr, familyId]
  );

  // Budget vs Actual
  const budgets = query(
    `SELECT b.category_id, b.amount as budget, c.name, c.icon, c.color
     FROM budgets b
     JOIN categories c ON b.category_id = c.id
     WHERE b.family_id = ? AND b.month = ? AND b.year = ?`,
    [familyId, currentMonth, currentYear]
  );

  const budgetVsActual = budgets.map(b => {
    const actualResult = query(
      `SELECT COALESCE(SUM(amount), 0) as actual FROM transactions
       WHERE family_id = ? AND category_id = ? AND strftime('%m', date) = ? AND strftime('%Y', date) = ? AND type = 'expense'`,
      [familyId, b.category_id, monthStr, yearStr]
    );
    return {
      ...b,
      actual: actualResult[0]?.actual || 0
    };
  });

  // Alerts
  const alerts = [];
  budgetVsActual.forEach(item => {
    const percentage = (item.actual / item.budget) * 100;
    if (percentage >= 100) {
      alerts.push({ type: 'danger', message: `Budget ${item.name} sudah melebihi batas!`, icon: item.icon });
    } else if (percentage >= 80) {
      alerts.push({ type: 'warning', message: `Budget ${item.name} tersisa ${(100 - percentage).toFixed(0)}%`, icon: item.icon });
    }
  });

  res.json({
    income,
    expense,
    balance: income - expense,
    expensesByCategory,
    budgetVsActual,
    alerts
  });
});

// Reports - Monthly trend (Family user authenticated)
app.get('/api/reports/trend', authenticateUser, (req, res) => {
  const { year } = req.query;
  const currentYear = parseInt(year) || new Date().getFullYear();

  // Check if this is a superadmin request with family context
  const familyId = req.superadmin ? (req.query.familyId ? parseInt(req.query.familyId) : req.user.family_id) : req.user.family_id;

  const trend = query(
    `SELECT
      strftime('%m', date) as month,
      SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as income,
      SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as expense
    FROM transactions
    WHERE family_id = ? AND strftime('%Y', date) = ?
    GROUP BY strftime('%m', date)
    ORDER BY month`,
    [familyId, String(currentYear)]
  );

  res.json(trend);
});

// ============ FAMILY MANAGEMENT API ============

// Get family profile (Family user authenticated)
app.get('/api/family', authenticateUser, (req, res) => {
  // Check if this is a superadmin request with family context
  const familyId = req.superadmin ? req.user.family_id : req.user.family_id;

  const family = query('SELECT * FROM families WHERE id = ?', [familyId]);
  const members = query('SELECT id, name, email, avatar, role, is_active FROM users WHERE family_id = ? AND is_active = 1 ORDER BY role DESC, name', [familyId]);
  const memberCount = members.length;

  res.json({
    profile: family[0] || { name: 'Keluarga Anda' },
    members,
    memberCount,
    maxMembers: 3, // Changed to 3 as requested
    canAddMore: memberCount < 3
  });
});

// Update family profile (Family user authenticated - only admin)
app.put('/api/family/profile', authenticateUser, (req, res) => {
  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can update any family profile
    const { name } = req.body;
    const familyId = req.body.family_id || req.user.family_id; // Use family_id from request body or session context

    // Verify family exists
    const family = query('SELECT * FROM families WHERE id = ?', [familyId]);
    if (family.length === 0) {
      return res.status(404).json({ error: 'Family not found' });
    }

    run('UPDATE families SET name = ? WHERE id = ?', [name, familyId]);
    res.json({ success: true, name });
  } else {
    // Regular user - only admin can update
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only admin can update family profile' });
    }

    const { name } = req.body;

    run('UPDATE families SET name = ? WHERE id = ?', [name, req.user.family_id]);
    res.json({ success: true, name });
  }
});

// Get all family members (Family user authenticated)
app.get('/api/family/members', authenticateUser, (req, res) => {
  // Check if this is a superadmin request with family context
  const familyId = req.superadmin ? req.user.family_id : req.user.family_id;

  const members = query('SELECT id, name, email, avatar, role, is_active FROM users WHERE family_id = ? AND is_active = 1 ORDER BY role DESC, name', [familyId]);
  res.json(members);
});

// Add new family member (Family user authenticated - only admin)
app.post('/api/family/members', authenticateUser, async (req, res) => {
  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can add members to any family
    const { name, email, avatar, role } = req.body;
    const familyId = req.body.family_id || req.user.family_id; // Use family_id from request body or session context

    // Verify family exists
    const family = query('SELECT * FROM families WHERE id = ?', [familyId]);
    if (family.length === 0) {
      return res.status(404).json({ error: 'Family not found' });
    }

    // Check member count limit - now 3 per family as requested
    const countResult = query('SELECT COUNT(*) as count FROM users WHERE family_id = ? AND is_active = 1', [familyId]);
    const currentCount = countResult[0]?.count || 0;

    if (currentCount >= 3) { // Changed to 3 as requested
      return res.status(400).json({
        error: 'Maksimal 3 anggota keluarga. Hapus anggota lain untuk menambah yang baru.'
      });
    }

    // Validate role
    const memberRole = role === 'admin' ? 'admin' : 'member';

    // Hash default password
    const defaultPassword = memberRole === 'admin' ? 'admin123' : 'member123';
    const passwordHash = await bcrypt.hash(defaultPassword, 10);

    const result = run(
      'INSERT INTO users (family_id, name, email, password_hash, avatar, role) VALUES (?, ?, ?, ?, ?, ?)',
      [familyId, name, email || '', passwordHash, avatar || '👤', memberRole]
    );

    if (result.error) {
      return res.status(500).json({ error: result.error });
    }

    res.json({
      id: result.lastId,
      name,
      email: email || '',
      avatar: avatar || '👤',
      role: memberRole,
      is_active: 1,
      family_id: familyId
    });
  } else {
    // Regular user - only admin can add members
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only admin can add family members' });
    }

    const { name, email, avatar, role } = req.body;

    // Check member count limit - now 3 per family as requested
    const countResult = query('SELECT COUNT(*) as count FROM users WHERE family_id = ? AND is_active = 1', [req.user.family_id]);
    const currentCount = countResult[0]?.count || 0;

    if (currentCount >= 3) { // Changed to 3 as requested
      return res.status(400).json({
        error: 'Maksimal 3 anggota keluarga. Hapus anggota lain untuk menambah yang baru.'
      });
    }

    // Validate role
    const memberRole = role === 'admin' ? 'admin' : 'member';

    // Hash default password
    const defaultPassword = 'member123';
    const passwordHash = await bcrypt.hash(defaultPassword, 10);

    const result = run(
      'INSERT INTO users (family_id, name, email, password_hash, avatar, role) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.family_id, name, email || '', passwordHash, avatar || '👤', memberRole]
    );

    if (result.error) {
      return res.status(500).json({ error: result.error });
    }

    res.json({
      id: result.lastId,
      name,
      email: email || '',
      avatar: avatar || '👤',
      role: memberRole,
      is_active: 1
    });
  }
});

// Update family member (Family user authenticated - only admin)
app.put('/api/family/members/:id', authenticateUser, async (req, res) => {
  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can update members in any family
    const { name, email, avatar, role } = req.body;
    const memberId = parseInt(req.params.id);
    const familyId = req.body.family_id || req.user.family_id; // Use family_id from request body or session context

    // Verify family exists
    const family = query('SELECT * FROM families WHERE id = ?', [familyId]);
    if (family.length === 0) {
      return res.status(404).json({ error: 'Family not found' });
    }

    // Verify member belongs to specified family
    const member = query('SELECT * FROM users WHERE id = ? AND family_id = ?', [memberId, familyId]);
    if (member.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Member does not belong to specified family' });
    }

    // Check if this is the last admin
    if (role === 'member') {
      const admins = query('SELECT COUNT(*) as count FROM users WHERE family_id = ? AND role = ? AND is_active = 1', [familyId, 'admin']);
      const currentMember = query('SELECT role FROM users WHERE id = ? AND family_id = ?', [memberId, familyId]);

      if (currentMember[0]?.role === 'admin' && admins[0]?.count <= 1) {
        return res.status(400).json({
          error: 'Tidak bisa mengubah role admin terakhir. Minimal harus ada 1 admin.'
        });
      }
    }

    // Update password if role changes to admin
    let passwordHash = member[0].password_hash;
    if (role === 'admin' && member[0].role !== 'admin') {
      // If changing to admin, set a default admin password
      passwordHash = await bcrypt.hash('admin123', 10);
    }

    run(
      'UPDATE users SET name = ?, email = ?, avatar = ?, role = ?, password_hash = ? WHERE id = ? AND family_id = ?',
      [name, email || '', avatar || '👤', role || 'member', passwordHash, memberId, familyId]
    );

    res.json({ id: memberId, name, email, avatar, role, family_id: familyId });
  } else {
    // Regular user - only admin can update members
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only admin can update family members' });
    }

    const { name, email, avatar, role } = req.body;
    const memberId = parseInt(req.params.id);

    // Verify member belongs to user's family
    const member = query('SELECT * FROM users WHERE id = ? AND family_id = ?', [memberId, req.user.family_id]);
    if (member.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Member does not belong to your family' });
    }

    // Check if this is the last admin
    if (role === 'member') {
      const admins = query('SELECT COUNT(*) as count FROM users WHERE family_id = ? AND role = ? AND is_active = 1', [req.user.family_id, 'admin']);
      const currentMember = query('SELECT role FROM users WHERE id = ? AND family_id = ?', [memberId, req.user.family_id]);

      if (currentMember[0]?.role === 'admin' && admins[0]?.count <= 1) {
        return res.status(400).json({
          error: 'Tidak bisa mengubah role admin terakhir. Minimal harus ada 1 admin.'
        });
      }
    }

    // Update password if role changes to admin
    let passwordHash = member[0].password_hash;
    if (role === 'admin' && member[0].role !== 'admin') {
      // If changing to admin, set a default admin password
      passwordHash = await bcrypt.hash('admin123', 10);
    }

    run(
      'UPDATE users SET name = ?, email = ?, avatar = ?, role = ?, password_hash = ? WHERE id = ? AND family_id = ?',
      [name, email || '', avatar || '👤', role || 'member', passwordHash, memberId, req.user.family_id]
    );

    res.json({ id: memberId, name, email, avatar, role });
  }
});

// Delete (soft delete) family member (Family user authenticated - only admin)
app.delete('/api/family/members/:id', authenticateUser, (req, res) => {
  // Check if this is a superadmin request with family context
  if (req.superadmin) {
    // Superadmin can delete members from any family
    const memberId = parseInt(req.params.id);
    const familyId = req.body.family_id || req.user.family_id; // Use family_id from request body or session context

    // Verify family exists
    const family = query('SELECT * FROM families WHERE id = ?', [familyId]);
    if (family.length === 0) {
      return res.status(404).json({ error: 'Family not found' });
    }

    // Verify member belongs to specified family
    const member = query('SELECT * FROM users WHERE id = ? AND family_id = ?', [memberId, familyId]);
    if (member.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Member does not belong to specified family' });
    }

    // Check if this is the last admin
    if (member[0]?.role === 'admin') {
      const admins = query('SELECT COUNT(*) as count FROM users WHERE family_id = ? AND role = ? AND is_active = 1 AND id != ?', [familyId, 'admin', memberId]);
      if (admins[0]?.count <= 0) {
        return res.status(400).json({
          error: 'Tidak bisa menghapus admin terakhir. Minimal harus ada 1 admin.'
        });
      }
    }

    // Soft delete
    run('UPDATE users SET is_active = 0 WHERE id = ? AND family_id = ?', [memberId, familyId]);

    res.json({ success: true, family_id: familyId });
  } else {
    // Regular user - only admin can delete members
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only admin can delete family members' });
    }

    const memberId = parseInt(req.params.id);

    // Verify member belongs to user's family
    const member = query('SELECT * FROM users WHERE id = ? AND family_id = ?', [memberId, req.user.family_id]);
    if (member.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Member does not belong to your family' });
    }

    // Check if this is the last admin
    if (member[0]?.role === 'admin') {
      const admins = query('SELECT COUNT(*) as count FROM users WHERE family_id = ? AND role = ? AND is_active = 1 AND id != ?', [req.user.family_id, 'admin', memberId]);
      if (admins[0]?.count <= 0) {
        return res.status(400).json({
          error: 'Tidak bisa menghapus admin terakhir. Minimal harus ada 1 admin.'
        });
      }
    }

    // Soft delete
    run('UPDATE users SET is_active = 0 WHERE id = ? AND family_id = ?', [memberId, req.user.family_id]);

    res.json({ success: true });
  }
});

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve the main app - only for authenticated users
app.get('*', (req, res) => {
  // Check if user is trying to access main app without authentication
  const sessionId = req.headers['x-session-id'] || req.query.sessionId;

  // Allow access to login page without authentication
  if (req.path === '/login') {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
    return;
  }

  // For other routes, check if user is authenticated
  if (!sessionId && !req.path.startsWith('/api/')) {
    res.redirect('/login');
    return;
  }

  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
async function start() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`🚀 Family Finance Dashboard running at http://localhost:${PORT}`);
  });
}

start();
