// db.js  (Postgres)
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

module.exports = {
  // Basic query helper
  query: (text, params) => pool.query(text, params),

  // Optional: SQLite-style helpers used elsewhere in your app
  all: async (text, params = []) => {
    const result = await pool.query(text, params);
    return result.rows;
  },

  get: async (text, params = []) => {
    const result = await pool.query(text, params);
    return result.rows[0] || null;
  },

  run: async (text, params = []) => {
    await pool.query(text, params);
  },
};
