CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO products (id, name, category, price, stock) VALUES
    (1, 'Wireless Mouse', 'Electronics', 29.99, 150),
    (2, 'Mechanical Keyboard', 'Electronics', 89.99, 75),
    (3, 'USB-C Hub', 'Electronics', 49.99, 200),
    (4, 'Standing Desk', 'Furniture', 399.99, 30),
    (5, 'Ergonomic Chair', 'Furniture', 299.99, 45),
    (6, 'Monitor Arm', 'Furniture', 79.99, 120),
    (7, 'Notebook Pack (3)', 'Office Supplies', 12.99, 500),
    (8, 'Ballpoint Pens (10)', 'Office Supplies', 8.99, 800),
    (9, 'Webcam HD', 'Electronics', 59.99, 90),
    (10, 'Desk Lamp', 'Furniture', 44.99, 110);
