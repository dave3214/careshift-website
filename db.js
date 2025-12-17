// db.js  (Postgres version)
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

module.exports = {
  // Core helper – used everywhere
  query: (text, params) => pool.query(text, params),

  // Helpers that behave like the old SQLite functions
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
