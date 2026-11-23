const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
require('dotenv').config();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined });
(async () => {
  try {
    const sql = fs.readFileSync(path.join(__dirname, 'db/schema.sql'), 'utf8');
    await pool.query(sql);
    console.log('Database schema is up to date');
  } catch (error) {
    console.error('Database migration failed:', error.message);
    process.exitCode = 1;
  } finally { await pool.end(); }
})();