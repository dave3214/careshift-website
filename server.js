// server.js
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Ensure uploads folder exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Multer storage for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const safeName = file.originalname.replace(/\s+/g, '_');
    cb(null, uniqueSuffix + '-' + safeName);
  },
});
const upload = multer({ storage });

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files (CSS, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));
// Serve uploaded documents
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// To read form data (POST)
app.use(express.urlencoded({ extended: false }));

// Session middleware
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.sqlite' }),
    secret: 'CHANGE_THIS_SECRET', // change this in real projects
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

// Make user available in all views
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

// Middleware to protect routes
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

/* ========================================================
   WORKER: MY SHIFTS + ATTENDANCE + STATUS
   ======================================================== */

// Worker "My shifts" page
app.get('/my-shifts', requireLogin, (req, res) => {
  const user = req.session.user;

  // Only worker-type roles use this page
  if (!['staff', 'worker', 'nurse'].includes(user.role)) {
    return res.redirect('/dashboard');
  }

  const sql = `
    SELECT
      s.*,
      a.clock_in,
      a.clock_out,
      a.clock_in_reason,
      a.clock_out_reason
    FROM shifts s
    LEFT JOIN shift_attendance a
      ON a.shift_id = s.id
      AND a.user_id = s.user_id
    WHERE s.user_id = ?
    ORDER BY s.date, s.start_time
  `;

  db.all(sql, [user.id], (err, rows) => {
    if (err) {
      console.error('Error loading worker shifts', err);
      return res.render('my-shifts', {
        user,
        shifts: [],
        error: 'Could not load your shifts.',
      });
    }

    res.render('my-shifts', {
      user,
      shifts: rows || [],
      error: null,
    });
  });
});

// Worker: clock in to a shift
app.post('/shifts/:id/clock-in', requireLogin, (req, res) => {
  const user = req.session.user;
  const shiftId = req.params.id;
  const nowIso = new Date().toISOString();

  // Check if attendance row already exists
  db.get(
    'SELECT id, clock_in FROM shift_attendance WHERE shift_id = ? AND user_id = ?',
    [shiftId, user.id],
    (err, existing) => {
      if (err) {
        console.error('Error checking attendance row', err);
        return res.redirect('/my-shifts');
      }

      if (existing) {
        // Only set clock_in if it is still null
        db.run(
          'UPDATE shift_attendance SET clock_in = COALESCE(clock_in, ?) WHERE id = ?',
          [nowIso, existing.id],
          (err2) => {
            if (err2) console.error('Error updating clock_in', err2);
            return res.redirect('/my-shifts');
          }
        );
      } else {
        // Create new attendance row
        db.run(
          'INSERT INTO shift_attendance (shift_id, user_id, clock_in) VALUES (?,?,?)',
          [shiftId, user.id, nowIso],
          (err2) => {
            if (err2) console.error('Error inserting clock_in', err2);
            return res.redirect('/my-shifts');
          }
        );
      }
    }
  );
});

// Worker: clock out of a shift
app.post('/shifts/:id/clock-out', requireLogin, (req, res) => {
  const user = req.session.user;
  const shiftId = req.params.id;
  const nowIso = new Date().toISOString();

  db.get(
    'SELECT id, clock_out FROM shift_attendance WHERE shift_id = ? AND user_id = ?',
    [shiftId, user.id],
    (err, existing) => {
      if (err) {
        console.error('Error checking attendance row', err);
        return res.redirect('/my-shifts');
      }

      if (existing) {
        db.run(
          'UPDATE shift_attendance SET clock_out = COALESCE(clock_out, ?) WHERE id = ?',
          [nowIso, existing.id],
          (err2) => {
            if (err2) console.error('Error updating clock_out', err2);
            return res.redirect('/my-shifts');
          }
        );
      } else {
        db.run(
          'INSERT INTO shift_attendance (shift_id, user_id, clock_out) VALUES (?,?,?)',
          [shiftId, user.id, nowIso],
          (err2) => {
            if (err2) console.error('Error inserting clock_out', err2);
            return res.redirect('/my-shifts');
          }
        );
      }
    }
  );
});

// Worker: update shift status (assigned/completed/cancelled)
app.post('/my-shifts/update-status', requireLogin, (req, res) => {
  const user = req.session.user;
  const { shift_id, status } = req.body;

  const allowedStatuses = ['assigned', 'completed', 'cancelled'];

  if (!shift_id || !status || !allowedStatuses.includes(status)) {
    return res.redirect('/my-shifts');
  }

  // First, load the shift to check ownership + current status and details
  db.get(
    `
    SELECT
      id,
      user_id,
      status,
      date,
      start_time,
      end_time,
      location,
      role,
      notes,
      created_by_user_id
    FROM shifts
    WHERE id = ?
    `,
    [shift_id],
    (err, shift) => {
      if (err) {
        console.error(err);
        return res.redirect('/my-shifts');
      }

      // No such shift or not owned by this user
      if (!shift || shift.user_id !== user.id) {
        return res.redirect('/my-shifts');
      }

      // If already cancelled, do NOT allow further changes
      if (shift.status === 'cancelled') {
        return res.redirect('/my-shifts');
      }

      const newStatus = status;

      const stmt = db.prepare(
        'UPDATE shifts SET status = ? WHERE id = ? AND user_id = ?'
      );

      stmt.run(newStatus, shift_id, user.id, (err2) => {
        if (err2) {
          console.error(err2);
          return res.redirect('/my-shifts');
        }

        // If worker cancelled the shift, create a new open shift
        if (newStatus === 'cancelled') {
          const createdBy =
            shift.created_by_user_id && shift.created_by_user_id !== user.id
              ? shift.created_by_user_id
              : user.id;

          const insertOpen = db.prepare(`
            INSERT INTO open_shifts (
              date,
              start_time,
              end_time,
              location,
              role,
              notes,
              status,
              created_by_user_id,
              assigned_user_id,
              filled_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'open', ?, NULL, NULL)
          `);

          insertOpen.run(
            shift.date,
            shift.start_time,
            shift.end_time,
            shift.location,
            shift.role,
            shift.notes,
            createdBy,
            (err3) => {
              if (err3) {
                console.error(err3);
              }
              return res.redirect('/my-shifts');
            }
          );
        } else {
          // For non-cancel changes, just go back
          return res.redirect('/my-shifts');
        }
      });
    }
  );
});

/* ========================================================
   AUTH & HOME
   ======================================================== */

// Home / Landing
app.get('/', (req, res) => {
  res.render('home');
});

// Register form
app.get('/register', (req, res) => {
  const presetRole = req.query.role || '';
  res.render('register', { error: null, presetRole });
});

// Handle registration
app.post('/register', async (req, res) => {
  const {
    name,
    email,
    password,
    role,
    provider_name,
    provider_service_type,
    provider_locations,
    provider_roles_skill_mix,
  } = req.body;

  if (!name || !email || !password || !role) {
    return res.render('register', {
      error: 'Please fill in all required fields.',
      presetRole: role,
    });
  }

  if (!['manager', 'staff', 'nurse'].includes(role)) {
    return res.render('register', {
      error: 'Invalid role selected.',
      presetRole: role,
    });
  }

  if (role === 'manager' && !provider_name) {
    return res.render('register', {
      error: 'Please provide your care provider name (care home or agency).',
      presetRole: role,
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    const insertUser = db.prepare(
      'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)'
    );

    insertUser.run(name, email, passwordHash, role, function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed: users.email')) {
          return res.render('register', {
            error: 'Email already registered.',
            presetRole: role,
          });
        }
        console.error(err);
        return res.render('register', {
          error: 'Something went wrong. Try again.',
          presetRole: role,
        });
      }

      const newUserId = this.lastID;

      if (role === 'manager') {
        const insertProvider = db.prepare(
          `
          INSERT INTO providers
            (name, service_type, locations, roles_skill_mix, created_by_user_id)
          VALUES (?, ?, ?, ?, ?)
        `
        );

        insertProvider.run(
          provider_name,
          provider_service_type || null,
          provider_locations || null,
          provider_roles_skill_mix || null,
          newUserId,
          function (err2) {
            if (err2) {
              console.error(err2);
            }

            req.session.user = {
              id: newUserId,
              name,
              email,
              role,
            };

            res.redirect('/dashboard');
          }
        );
      } else {
        req.session.user = {
          id: newUserId,
          name,
          email,
          role,
        };

        res.redirect('/dashboard');
      }
    });
  } catch (error) {
    console.error(error);
    res.render('register', {
      error: 'Error creating account.',
      presetRole: role,
    });
  }
});

// Login form
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Handle login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('login', {
      error: 'Please enter email and password.',
    });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      console.error(err);
      return res.render('login', { error: 'Something went wrong.' });
    }

    if (!user) {
      return res.render('login', { error: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.render('login', { error: 'Invalid email or password.' });
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    res.redirect('/dashboard');
  });
});

/* ========================================================
   DASHBOARD
   ======================================================== */

app.get('/dashboard', requireLogin, (req, res) => {
  const user = req.session.user;
  const todayStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

  // MANAGER DASHBOARD
  if (user.role === 'manager') {
    db.all(
      'SELECT * FROM providers WHERE created_by_user_id = ? ORDER BY created_at DESC',
      [user.id],
      (err, providers) => {
        if (err) {
          console.error(err);
          return res.render('dashboard', {
            user,
            providers: [],
            shiftRequests: [],
            managerToday: null,
            workerToday: null,
            error: 'Could not load provider data.',
          });
        }

        const sqlRequests = `
          SELECT
            os.*,
            u.name  AS worker_name,
            u.role  AS worker_role,
            u.email AS worker_email
          FROM open_shifts os
          JOIN users u ON os.assigned_user_id = u.id
          WHERE os.created_by_user_id = ?
            AND os.status = 'requested'
          ORDER BY os.date, os.start_time
        `;

        db.all(sqlRequests, [user.id], (err2, shiftRequests) => {
          if (err2) {
            console.error(err2);
            return res.render('dashboard', {
              user,
              providers,
              shiftRequests: [],
              managerToday: null,
              workerToday: null,
              error: 'Could not load shift requests.',
            });
          }

          const sqlOpenCount = `
            SELECT COUNT(*) AS openCount
            FROM open_shifts
            WHERE created_by_user_id = ?
              AND status = 'open'
          `;

          db.get(sqlOpenCount, [user.id], (err3, rowOpen) => {
            if (err3) {
              console.error(err3);
            }

            const openShiftsOpenCount = rowOpen ? rowOpen.openCount : 0;
            const pendingRequestsCount = shiftRequests.length;

            const managerToday = {
              pendingRequestsCount,
              openShiftsOpenCount,
            };

            return res.render('dashboard', {
              user,
              providers,
              shiftRequests,
              managerToday,
              workerToday: null,
              error: null,
            });
          });
        });
      }
    );
  } else {
    // WORKER DASHBOARD
    const nextShiftSql = `
      SELECT *
      FROM shifts
      WHERE user_id = ?
        AND date >= ?
      ORDER BY date, start_time
      LIMIT 1
    `;

    db.get(nextShiftSql, [user.id, todayStr], (err1, nextShift) => {
      if (err1) {
        console.error(err1);
        return res.render('dashboard', {
          user,
          providers: [],
          shiftRequests: [],
          managerToday: null,
          workerToday: null,
          error: 'Could not load today data.',
        });
      }

      const upcomingCountSql = `
        SELECT COUNT(*) AS upcomingCount
        FROM shifts
        WHERE user_id = ?
          AND date >= ?
      `;

      db.get(upcomingCountSql, [user.id, todayStr], (err2, rowUpcoming) => {
        if (err2) {
          console.error(err2);
          return res.render('dashboard', {
            user,
            providers: [],
            shiftRequests: [],
            managerToday: null,
            workerToday: null,
            error: 'Could not load today data.',
          });
        }

        const pendingRequestsSql = `
          SELECT COUNT(*) AS pendingRequestsCount
          FROM open_shifts
          WHERE assigned_user_id = ?
            AND status = 'requested'
        `;

        db.get(pendingRequestsSql, [user.id], (err3, rowReq) => {
          if (err3) {
            console.error(err3);
          }

          const workerToday = {
            nextShift: nextShift || null,
            upcomingCount: rowUpcoming ? rowUpcoming.upcomingCount : 0,
            pendingRequestsCount: rowReq ? rowReq.pendingRequestsCount : 0,
          };

          return res.render('dashboard', {
            user,
            providers: [],
            shiftRequests: [],
            managerToday: null,
            workerToday,
            error: null,
          });
        });
      });
    });
  }
});

/* ========================================================
   MANAGER: ASSIGN SHIFTS & VIEW SHIFTS
   ======================================================== */

// Assign shift (GET)
app.get('/assign-shift', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can assign shifts.');
  }

  db.all(
    "SELECT id, name, role, email FROM users WHERE role IN ('staff', 'nurse') ORDER BY name",
    [],
    (err, workers) => {
      if (err) {
        console.error(err);
        return res.render('assign-shift', {
          user,
          workers: [],
          error: 'Could not load workers.',
          success: null,
        });
      }

      res.render('assign-shift', {
        user,
        workers,
        error: null,
        success: null,
      });
    }
  );
});

// Assign shift (POST) - save to DB
app.post('/assign-shift', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can assign shifts.');
  }

  const { worker_id, date, start_time, end_time, location, role, notes } = req.body;

  const renderWithWorkers = (errorMsg, successMsg) => {
    db.all(
      "SELECT id, name, role, email FROM users WHERE role IN ('staff', 'nurse') ORDER BY name",
      [],
      (err, workers) => {
        if (err) {
          console.error(err);
          return res.render('assign-shift', {
            user,
            workers: [],
            error: errorMsg || 'Could not load workers.',
            success: null,
          });
        }

        return res.render('assign-shift', {
          user,
          workers,
          error: errorMsg,
          success: successMsg,
        });
      }
    );
  };

  if (!worker_id || !date || !start_time || !end_time) {
    return renderWithWorkers(
      'Please fill in all required fields (worker, date, start and end time).',
      null
    );
  }

  const stmt = db.prepare(
    `
    INSERT INTO shifts (
      user_id, date, start_time, end_time, location, role, status, notes, created_by_user_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
  );

  stmt.run(
    worker_id,
    date,
    start_time,
    end_time,
    location || null,
    role || null,
    'assigned',
    notes || null,
    user.id,
    (err) => {
      if (err) {
        console.error(err);
        return renderWithWorkers('Could not save shift.', null);
      }

      return renderWithWorkers(null, 'Shift assigned successfully.');
    }
  );
});

// Manager shifts list
app.get('/manager-shifts', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can view this page.');
  }

  const { status, date_from, date_to } = req.query;
  const allowedStatuses = ['assigned', 'completed', 'cancelled'];

  let sql = `
    SELECT
      s.*,
      u.name AS worker_name,
      u.role AS worker_role,
      u.email AS worker_email
    FROM shifts s
    JOIN users u ON s.user_id = u.id
    WHERE s.created_by_user_id = ?
  `;

  const params = [user.id];

  if (status && allowedStatuses.includes(status)) {
    sql += ' AND s.status = ?';
    params.push(status);
  }

  if (date_from) {
    sql += ' AND date(s.date) >= date(?)';
    params.push(date_from);
  }

  if (date_to) {
    sql += ' AND date(s.date) <= date(?)';
    params.push(date_to);
  }

  sql += ' ORDER BY s.date, s.start_time';

  db.all(sql, params, (err, shifts) => {
    if (err) {
      console.error(err);
      return res.render('manager-shifts', {
        user,
        shifts: [],
        error: 'Could not load shifts.',
        filterStatus: status || '',
        filterFrom: date_from || '',
        filterTo: date_to || '',
      });
    }

    res.render('manager-shifts', {
      user,
      shifts,
      error: null,
      filterStatus: status || '',
      filterFrom: date_from || '',
      filterTo: date_to || '',
    });
  });
});

// Manager cancels a shift
app.post('/manager-shifts/cancel', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can cancel shifts.');
  }

  const { shift_id } = req.body;
  if (!shift_id) {
    return res.redirect('/manager-shifts');
  }

  const stmt = db.prepare(
    'UPDATE shifts SET status = ? WHERE id = ? AND created_by_user_id = ?'
  );

  stmt.run('cancelled', shift_id, user.id, (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/manager-shifts');
  });
});

/* ========================================================
   WEEKLY ROTA
   ======================================================== */

app.get('/rota-week', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can view the rota.');
  }

  const { week_start } = req.query;

  function formatDate(d) {
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  let startDateStr;

  if (week_start) {
    startDateStr = week_start;
  } else {
    const today = new Date();
    const day = today.getDay(); // 0 = Sunday
    const diffToMonday = (day + 6) % 7; // days since Monday
    const monday = new Date(today);
    monday.setDate(today.getDate() - diffToMonday);
    startDateStr = formatDate(monday);
  }

  const startDate = new Date(startDateStr);
  const endDate = new Date(startDate);
  endDate.setDate(startDate.getDate() + 6);
  const endDateStr = formatDate(endDate);

  const dayNames = [
    'Monday',
    'Tuesday',
    'Wednesday',
    'Thursday',
    'Friday',
    'Saturday',
    'Sunday',
  ];
  const days = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(startDate);
    d.setDate(startDate.getDate() + i);
    days.push({
      label: `${dayNames[i]} (${formatDate(d)})`,
      date: formatDate(d),
    });
  }

  const sql = `
    SELECT
      s.*,
      u.name AS worker_name,
      u.role AS worker_role
    FROM shifts s
    JOIN users u ON s.user_id = u.id
    WHERE s.created_by_user_id = ?
      AND date(s.date) BETWEEN date(?) AND date(?)
    ORDER BY s.date, s.start_time
  `;

  db.all(sql, [user.id, startDateStr, endDateStr], (err, shifts) => {
    if (err) {
      console.error(err);
      return res.render('rota-week', {
        user,
        days,
        shifts: [],
        startDateStr,
        endDateStr,
        error: 'Could not load shifts for this week.',
      });
    }

    res.render('rota-week', {
      user,
      days,
      shifts,
      startDateStr,
      endDateStr,
      error: null,
    });
  });
});

/* ========================================================
   OPEN SHIFTS / MARKETPLACE
   ======================================================== */

// Manager: view and create open shifts
app.get('/open-shifts/manage', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can manage open shifts.');
  }

  const sql = `
    SELECT os.*, u.name AS assigned_worker_name
    FROM open_shifts os
    LEFT JOIN users u ON os.assigned_user_id = u.id
    WHERE os.created_by_user_id = ?
    ORDER BY os.date, os.start_time
  `;

  db.all(sql, [user.id], (err, openShifts) => {
    if (err) {
      console.error(err);
      return res.render('open-shifts-manage', {
        user,
        openShifts: [],
        error: 'Could not load open shifts.',
      });
    }

    res.render('open-shifts-manage', {
      user,
      openShifts,
      error: null,
    });
  });
});

// Manager: create an open shift
app.post('/open-shifts/manage', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can create open shifts.');
  }

  const { date, start_time, end_time, location, role, notes } = req.body;

  if (!date || !start_time || !end_time) {
    return res.redirect('/open-shifts/manage');
  }

  const stmt = db.prepare(`
    INSERT INTO open_shifts (
      date, start_time, end_time, location, role, notes, status, created_by_user_id
    )
    VALUES (?, ?, ?, ?, ?, ?, 'open', ?)
  `);

  stmt.run(
    date,
    start_time,
    end_time,
    location || null,
    role || null,
    notes || null,
    user.id,
    (err) => {
      if (err) {
        console.error(err);
      }
      res.redirect('/open-shifts/manage');
    }
  );
});

// Worker: view open shifts (find extra work)
app.get('/open-shifts', requireLogin, (req, res) => {
  const user = req.session.user;

  if (!['staff', 'nurse'].includes(user.role)) {
    return res.status(403).send('Only workers can view open shifts.');
  }

  const sql = `
    SELECT os.*, m.name AS manager_name
    FROM open_shifts os
    JOIN users m ON os.created_by_user_id = m.id
    WHERE os.status = 'open'
    ORDER BY os.date, os.start_time
  `;

  db.all(sql, [], (err, openShifts) => {
    if (err) {
      console.error(err);
      return res.render('open-shifts', {
        user,
        openShifts: [],
        error: 'Could not load open shifts.',
      });
    }

    res.render('open-shifts', {
      user,
      openShifts,
      error: null,
    });
  });
});

// Worker: claim an open shift (request approval)
app.post('/open-shifts/claim', requireLogin, (req, res) => {
  const user = req.session.user;

  if (!['staff', 'nurse'].includes(user.role)) {
    return res.status(403).send('Only workers can claim open shifts.');
  }

  const { open_shift_id } = req.body;
  if (!open_shift_id) {
    return res.redirect('/open-shifts');
  }

  db.get(
    `SELECT * FROM open_shifts WHERE id = ? AND status = 'open'`,
    [open_shift_id],
    (err, os) => {
      if (err) {
        console.error(err);
        return res.redirect('/open-shifts');
      }

      if (!os) {
        return res.redirect('/open-shifts');
      }

      const updateOpen = db.prepare(`
        UPDATE open_shifts
        SET status = 'requested',
            assigned_user_id = ?,
            filled_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'open'
      `);

      updateOpen.run(user.id, open_shift_id, (err2) => {
        if (err2) {
          console.error(err2);
        }
        res.redirect('/open-shifts');
      });
    }
  );
});

// Manager: approve a worker's request for an open shift
app.post('/open-shifts/approve', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can approve open shifts.');
  }

  const { open_shift_id } = req.body;
  if (!open_shift_id) {
    return res.redirect('/open-shifts/manage');
  }

  db.get(
    `SELECT * FROM open_shifts WHERE id = ? AND status = 'requested'`,
    [open_shift_id],
    (err, os) => {
      if (err) {
        console.error(err);
        return res.redirect('/open-shifts/manage');
      }

      if (!os || !os.assigned_user_id) {
        return res.redirect('/open-shifts/manage');
      }

      const insertShift = db.prepare(`
        INSERT INTO shifts (
          user_id, date, start_time, end_time, location, role, status, notes, created_by_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, 'assigned', ?, ?)
      `);

      insertShift.run(
        os.assigned_user_id,
        os.date,
        os.start_time,
        os.end_time,
        os.location,
        os.role,
        os.notes,
        os.created_by_user_id,
        (err2) => {
          if (err2) {
            console.error(err2);
            return res.redirect('/open-shifts/manage');
          }

          const updateOpen = db.prepare(`
            UPDATE open_shifts
            SET status = 'approved'
            WHERE id = ?
          `);

          updateOpen.run(open_shift_id, (err3) => {
            if (err3) {
              console.error(err3);
            }
            res.redirect('/open-shifts/manage');
          });
        }
      );
    }
  );
});

// Manager: reject a worker's request for an open shift
app.post('/open-shifts/reject', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can reject open shifts.');
  }

  const { open_shift_id } = req.body;
  if (!open_shift_id) {
    return res.redirect('/open-shifts/manage');
  }

  const stmt = db.prepare(`
    UPDATE open_shifts
    SET status = 'open',
        assigned_user_id = NULL,
        filled_at = NULL
    WHERE id = ? AND status = 'requested'
  `);

  stmt.run(open_shift_id, (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/open-shifts/manage');
  });
});

/* ========================================================
   WORKER DOCUMENTS & MANAGER REVIEW
   ======================================================== */

// Worker: profile & documents
app.get('/profile-documents', requireLogin, (req, res) => {
  const user = req.session.user;

  const sql = `
    SELECT * FROM documents
    WHERE user_id = ?
    ORDER BY uploaded_at DESC
  `;

  db.all(sql, [user.id], (err, docs) => {
    if (err) {
      console.error(err);
      return res.render('profile-documents', {
        user,
        docs: [],
        error: 'Could not load documents.',
      });
    }

    res.render('profile-documents', {
      user,
      docs,
      error: null,
    });
  });
});

// Worker: upload a document
app.post(
  '/profile-documents/upload',
  requireLogin,
  upload.single('document_file'),
  (req, res) => {
    const user = req.session.user;
    const { doc_type } = req.body;

    const allowedTypes = ['dbs', 'rtw', 'training', 'other'];

    if (!doc_type || !allowedTypes.includes(doc_type) || !req.file) {
      return res.redirect('/profile-documents');
    }

    const filePath = '/uploads/' + req.file.filename;
    const originalName = req.file.originalname;

    const stmt = db.prepare(`
      INSERT INTO documents (user_id, doc_type, file_path, original_name, status)
      VALUES (?, ?, ?, ?, 'pending')
    `);

    stmt.run(user.id, doc_type, filePath, originalName, (err) => {
      if (err) {
        console.error(err);
      }
      res.redirect('/profile-documents');
    });
  }
);

// Manager: review documents
app.get('/documents-review', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can review documents.');
  }

  const sql = `
    SELECT
      d.*,
      u.name AS user_name,
      u.role AS user_role,
      u.email AS user_email
    FROM documents d
    JOIN users u ON d.user_id = u.id
    ORDER BY d.status, d.uploaded_at DESC
  `;

  db.all(sql, [], (err, docs) => {
    if (err) {
      console.error(err);
      return res.render('documents-review', {
        user,
        docs: [],
        error: 'Could not load documents.',
      });
    }

    res.render('documents-review', {
      user,
      docs,
      error: null,
    });
  });
});

// Manager: verify a document
app.post('/documents-review/verify', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can verify documents.');
  }

  const { document_id } = req.body;
  if (!document_id) {
    return res.redirect('/documents-review');
  }

  const stmt = db.prepare(`
    UPDATE documents
    SET status = 'verified',
        verified_by_user_id = ?,
        verified_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `);

  stmt.run(user.id, document_id, (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/documents-review');
  });
});

// Manager: reject a document
app.post('/documents-review/reject', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can review documents.');
  }

  const { document_id } = req.body;
  if (!document_id) {
    return res.redirect('/documents-review');
  }

  const stmt = db.prepare(`
    UPDATE documents
    SET status = 'rejected',
        verified_by_user_id = ?,
        verified_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `);

  stmt.run(user.id, document_id, (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/documents-review');
  });
});

/* ========================================================
   MANAGER: ATTENDANCE OVERVIEW
   ======================================================== */

app.get('/manager/attendance', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.redirect('/dashboard');
  }

  const sql = `
    SELECT
      s.id AS shift_id,
      s.date,
      s.start_time,
      s.end_time,
      s.location,
      u.name  AS worker_name,
      u.email AS worker_email,
      a.clock_in,
      a.clock_out,
      a.clock_in_reason,
      a.clock_out_reason
    FROM shifts s
    JOIN users u
      ON s.user_id = u.id
    LEFT JOIN shift_attendance a
      ON a.shift_id = s.id
     AND a.user_id = s.user_id
    ORDER BY s.date DESC, s.start_time DESC
    LIMIT 100
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error(err);
      return res.render('manager-attendance', {
        user,
        attendance: [],
        error: 'Could not load shift attendance.',
      });
    }

    res.render('manager-attendance', {
      user,
      attendance: rows,
      error: null,
    });
  });
});

/* ========================================================
   LOGOUT & SERVER START
   ======================================================== */

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
