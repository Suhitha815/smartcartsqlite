PRAGMA foreign_keys = ON;

/* =========================
   ADMIN TABLE
========================= */
CREATE TABLE admin (
    admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    profile_image TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reset_token TEXT,
    token_expiry DATETIME
);

/* =========================
   USERS TABLE
========================= */
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reset_token TEXT,
    token_expiry DATETIME
);

/* =========================
   PRODUCTS TABLE
========================= */
CREATE TABLE products (
    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    category TEXT,
    price REAL,
    image TEXT
);

/* =========================
   ORDERS TABLE
========================= */
CREATE TABLE orders (
    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    razorpay_order_id TEXT,
    razorpay_payment_id TEXT,
    amount REAL,
    payment_status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    order_status TEXT DEFAULT 'Pending',

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

/* =========================
   ORDER ITEMS TABLE
========================= */
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    product_name TEXT,
    quantity INTEGER,
    price REAL,

    FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(product_id) ON DELETE CASCADE
);
