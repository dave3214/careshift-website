// db.js  (SQLite version)
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Main application database file
const dbFile = path.join(__dirname, 'database.sqlite');

// Open the database (it will be created automatically if it doesn't exist)
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Failed to open SQLite database:', err);
  } else {
    console.log('SQLite database opened at', dbFile);
  }
});

// Turn on foreign key support
db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');
});

module.exports = db;
