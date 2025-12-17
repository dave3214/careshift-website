// migrate-add-open-shift-postcode.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  console.log('Migrating database at', dbPath);

  db.run(
    "ALTER TABLE open_shifts ADD COLUMN shift_postcode TEXT",
    (err) => {
      if (err) {
        if (err.message.includes('duplicate column name')) {
          console.log('-> Column shift_postcode already exists, skipping');
        } else {
          console.error('Error adding shift_postcode:', err.message);
        }
      } else {
        console.log('-> Added shift_postcode column to open_shifts table');
      }
    }
  );
});

db.close(() => console.log('Migration finished.'));
