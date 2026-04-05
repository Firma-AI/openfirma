import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

const BASE_DIR = process.cwd();
const DB_PATH = path.join(BASE_DIR, '.data', 'firma.db');
const SEED_PATH = path.join(BASE_DIR, 'seed.sql');

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (!db) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
  }
  return db;
}

export function initializeDatabase(): void {
  const database = getDb();

  if (!fs.existsSync(SEED_PATH)) {
    console.log(`firma-agent: Seed file not found at ${SEED_PATH}, skipping initialization`);
    return;
  }

  const seedSql = fs.readFileSync(SEED_PATH, 'utf-8');
  database.exec(seedSql);
  console.log('firma-agent: Database initialized with seed data');
}
