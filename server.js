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

// ----------------------------------------------------
// File uploads (documents + profile photos)
// ----------------------------------------------------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const safeName = file.originalname.replace(/\s+/g, '_');
    cb(null, uniqueSuffix + '-' + safeName);
  },
});

const upload = multer({ storage });

// ----------------------------------------------------
// View engine & static files
// ----------------------------------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: false }));

// ----------------------------------------------------
// Sessions
// ----------------------------------------------------
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.sqlite' }),
    secret: 'CHANGE_THIS_SECRET',
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

// ----------------------------------------------------
// Helpers / middleware
// ----------------------------------------------------
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function diffMinutes(later, earlier) {
  return Math.round((later - earlier) / 60000);
}

// ----------------------------------------------------
// Worker: My Shifts + Attendance
// ----------------------------------------------------
app.get('/my-shifts', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'staff' && user.role !== 'worker' && user.role !== 'nurse') {
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
      console.error(err);
      return res.render('my-shifts', {
        user,
        shifts: [],
        error: 'Could not load your shifts.',
      });
    }

    res.render('my-shifts', {
      user,
      shifts: rows,
      error: null,
    });
  });
});

// Clock in (with potential reason if late)
app.post('/shifts/:id/clock-in', requireLogin, (req, res) => {
  const user = req.session.user;
  const shiftId = req.params.id;
  const reasonFromForm = (req.body.reason || '').trim();

  const now = new Date();
  const nowIso = now.toISOString();

  const sqlShift = 'SELECT * FROM shifts WHERE id = ? AND user_id = ?';
  db.get(sqlShift, [shiftId, user.id], (err, shift) => {
    if (err || !shift) {
      console.error(err);
      return res.redirect('/my-shifts');
    }

    const scheduledStart = new Date(`${shift.date}T${shift.start_time}:00`);
    const minutesLate = diffMinutes(now, scheduledStart); // positive if late
    const needsReason = minutesLate > 15;

    if (needsReason && !reasonFromForm) {
      return res.render('shift-reason', {
        user,
        shift,
        action: 'clock-in',
        error: null,
      });
    }

    const clockInReason = needsReason ? reasonFromForm : null;

    db.get(
      'SELECT id FROM shift_attendance WHERE shift_id = ? AND user_id = ?',
      [shiftId, user.id],
      (err2, existing) => {
        if (err2) {
          console.error(err2);
          return res.redirect('/my-shifts');
        }

        if (existing) {
          db.run(
            'UPDATE shift_attendance SET clock_in = ?, clock_in_reason = ? WHERE id = ?',
            [nowIso, clockInReason, existing.id],
            (err3) => {
              if (err3) console.error(err3);
              res.redirect('/my-shifts');
            }
          );
        } else {
          db.run(
            'INSERT INTO shift_attendance (shift_id, user_id, clock_in, clock_in_reason) VALUES (?,?,?,?)',
            [shiftId, user.id, nowIso, clockInReason],
            (err3) => {
              if (err3) console.error(err3);
              res.redirect('/my-shifts');
            }
          );
        }
      }
    );
  });
});

// Clock out (with potential reason if early/late)
app.post('/shifts/:id/clock-out', requireLogin, (req, res) => {
  const user = req.session.user;
  const shiftId = req.params.id;
  const reasonFromForm = (req.body.reason || '').trim();

  const now = new Date();
  const nowIso = now.toISOString();

  const sqlShift = 'SELECT * FROM shifts WHERE id = ? AND user_id = ?';
  db.get(sqlShift, [shiftId, user.id], (err, shift) => {
    if (err || !shift) {
      console.error(err);
      return res.redirect('/my-shifts');
    }

    const scheduledEnd = new Date(`${shift.date}T${shift.end_time}:00`);
    const minutesDiffFromEnd = Math.abs(diffMinutes(now, scheduledEnd));
    const needsReason = minutesDiffFromEnd > 15;

    if (needsReason && !reasonFromForm) {
      return res.render('shift-reason', {
        user,
        shift,
        action: 'clock-out',
        error: null,
      });
    }

    const clockOutReason = needsReason ? reasonFromForm : null;

    db.get(
      'SELECT id FROM shift_attendance WHERE shift_id = ? AND user_id = ?',
      [shiftId, user.id],
      (err2, existing) => {
        if (err2 || !existing) {
          if (err2) console.error(err2);
          return db.run(
            'INSERT INTO shift_attendance (shift_id, user_id, clock_out, clock_out_reason) VALUES (?,?,?,?)',
            [shiftId, user.id, nowIso, clockOutReason],
            (err3) => {
              if (err3) console.error(err3);
              res.redirect('/my-shifts');
            }
          );
        }

        db.run(
          'UPDATE shift_attendance SET clock_out = ?, clock_out_reason = ? WHERE id = ?',
          [nowIso, clockOutReason, existing.id],
          (err3) => {
            if (err3) console.error(err3);
            res.redirect('/my-shifts');
          }
        );
      }
    );
  });
});

// Worker updates shift status (includes creating open shift on cancel)
app.post('/my-shifts/update-status', requireLogin, (req, res) => {
  const user = req.session.user;
  const { shift_id, status } = req.body;

  const allowedStatuses = ['assigned', 'completed', 'cancelled'];

  if (!shift_id || !status || !allowedStatuses.includes(status)) {
    return res.redirect('/my-shifts');
  }

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

      if (!shift || shift.user_id !== user.id) {
        return res.redirect('/my-shifts');
      }

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

        // If worker cancels, create an open shift for others
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
          return res.redirect('/my-shifts');
        }
      });
    }
  );
});

// ----------------------------------------------------
// Home / Auth
// ----------------------------------------------------
app.get('/', (req, res) => {
  res.render('home');
});

// Show registration form
app.get('/register', (req, res) => {
  const presetRole = req.query.role || '';
  res.render('register', { error: null, presetRole });
});

// Handle registration (SQLite + profile photo)
app.post(
  '/register',
  upload.single('profile_photo'), // <-- profile photo upload
  async (req, res) => {
    const {
      name,
      email,
      password,
      role,
      provider_name,
      provider_service_type,
      provider_locations,
      provider_roles_skill_mix,
      house_number,
      street_name,
      city,
      postcode,
    } = req.body;

    const presetRole = role || '';

    // Basic validation
    if (!name || !email || !password || !role) {
      return res.render('register', {
        error: 'Please fill in all required fields.',
        presetRole,
      });
    }

    if (!['manager', 'staff', 'nurse'].includes(role)) {
      return res.render('register', {
        error: 'Invalid role selected.',
        presetRole,
      });
    }

    if (role === 'manager' && !provider_name) {
      return res.render('register', {
        error: 'Please provide your care provider / agency name.',
        presetRole,
      });
    }

    // If a file was uploaded, store its path. Otherwise null.
    const profilePhotoPath = req.file ? '/uploads/' + req.file.filename : null;

    try {
      // 1) Check if email already exists
      db.get('SELECT id FROM users WHERE email = ?', [email], async (err, existing) => {
        if (err) {
          console.error('Error checking existing user:', err);
          return res.render('register', {
            error: 'Something went wrong. Try again.',
            presetRole,
          });
        }

        if (existing) {
          return res.render('register', {
            error: 'Email already registered.',
            presetRole,
          });
        }

        // 2) Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // 3) Insert user (including profile_photo_path)
        const insertUserStmt = db.prepare(`
          INSERT INTO users (
            name,
            email,
            password_hash,
            role,
            house_number,
            street_name,
            city,
            postcode,
            profile_photo_path
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        insertUserStmt.run(
          name,
          email,
          passwordHash,
          role,
          house_number || null,
          street_name || null,
          city || null,
          postcode || null,
          profilePhotoPath,
          function (err2) {
            if (err2) {
              console.error('Error inserting user:', err2);
              return res.render('register', {
                error: 'Something went wrong. Try again.',
                presetRole,
              });
            }

            const newUserId = this.lastID;

            const finishAndRedirect = () => {
              req.session.user = {
                id: newUserId,
                name,
                email,
                role,
                profile_photo_path: profilePhotoPath,
              };
              res.redirect('/dashboard');
            };

            // 4) If manager, insert provider row
            if (role === 'manager') {
              const insertProviderStmt = db.prepare(`
                INSERT INTO providers (
                  name,
                  service_type,
                  locations,
                  roles_skill_mix,
                  created_by_user_id
                )
                VALUES (?, ?, ?, ?, ?)
              `);

              insertProviderStmt.run(
                provider_name,
                provider_service_type || null,
                provider_locations || null,
                provider_roles_skill_mix || null,
                newUserId,
                (err3) => {
                  if (err3) {
                    console.error('Error inserting provider:', err3);
                    // still log the user in even if provider insert fails
                  }
                  finishAndRedirect();
                }
              );
            } else {
              finishAndRedirect();
            }
          }
        );
      });
    } catch (err) {
      console.error('Error during registration:', err);
      return res.render('register', {
        error: 'Something went wrong. Try again.',
        presetRole,
      });
    }
  }
);

// Show login form
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Handle login (SQLite)
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('login', {
      error: 'Please enter email and password.',
    });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      console.error('Error during login lookup:', err);
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
      profile_photo_path: user.profile_photo_path || null,
    };

    res.redirect('/dashboard');
  });
});

// ----------------------------------------------------
// Dashboard (manager & worker)
// ----------------------------------------------------
app.get('/dashboard', requireLogin, (req, res) => {
  const user = req.session.user;
  const todayStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

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

// ----------------------------------------------------
// Manager: view list of workers with photo + address
// ----------------------------------------------------
app.get('/manager/workers', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can view workers.');
  }

  const sql = `
    SELECT
      id,
      name,
      email,
      role,
      profile_photo_path,
      house_number,
      street_name,
      city,
      postcode
    FROM users
    WHERE role IN ('staff', 'nurse')
    ORDER BY name
  `;

  db.all(sql, [], (err, workers) => {
    if (err) {
      console.error(err);
      return res.render('manager-workers', {
        user,
        workers: [],
        error: 'Could not load workers.',
      });
    }

    res.render('manager-workers', {
      user,
      workers,
      error: null,
    });
  });
});

// ----------------------------------------------------
// Manager: assign shifts & view shifts
// ----------------------------------------------------
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

app.post('/assign-shift', requireLogin, (req, res) => {
  const user = req.session.user;

  if (user.role !== 'manager') {
    return res.status(403).send('Only managers can assign shifts.');
  }

  const { worker_id, date, start_time, end_time, location, role, notes } =
    req.body;

  if (!worker_id || !date || !start_time || !end_time) {
    return db.all(
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

        return res.render('assign-shift', {
          user,
          workers,
          error:
            'Please fill in all required fields (worker, date, start and end time).',
          success: null,
        });
      }
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
        return db.all(
          "SELECT id, name, role, email FROM users WHERE role IN ('staff', 'nurse') ORDER BY name",
          [],
          (err2, workers) => {
            if (err2) {
              console.error(err2);
              return res.render('assign-shift', {
                user,
                workers: [],
                error: 'Could not save shift.',
                success: null,
              });
            }

            return res.render('assign-shift', {
              user,
              workers,
              error: 'Could not save shift.',
              success: null,
            });
          }
        );
      }

      db.all(
        "SELECT id, name, role, email FROM users WHERE role IN ('staff', 'nurse') ORDER BY name",
        [],
        (err2, workers) => {
          if (err2) {
            console.error(err2);
            return res.render('assign-shift', {
              user,
              workers: [],
              error: 'Shift saved, but could not reload workers.',
              success: null,
            });
          }

          return res.render('assign-shift', {
            user,
            workers,
            error: null,
            success: 'Shift assigned successfully.',
          });
        }
      );
    }
  );
});

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

// ----------------------------------------------------
// Weekly rota view (manager)
// ----------------------------------------------------
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
    const day = today.getDay(); // 0 = Sun, 1 = Mon, ...
    const diffToMonday = (day + 6) % 7;
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

// ----------------------------------------------------
// Open shifts (manager + worker)
// ----------------------------------------------------
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

// Worker: see open shifts
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

// Worker: claim open shift (request)
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

// Manager: approve / reject open shift requests
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

// ----------------------------------------------------
// Worker documents & manager review
// ----------------------------------------------------
// Worker: profile & documents
app.get('/profile-documents', requireLogin, (req, res) => {
  const sessionUser = req.session.user;

  const userSql = `
    SELECT
      id,
      name,
      email,
      role,
      profile_photo_path,
      house_number,
      street_name,
      city,
      postcode
    FROM users
    WHERE id = ?
  `;

  db.get(userSql, [sessionUser.id], (err, fullUser) => {
    if (err || !fullUser) {
      console.error(err);
      return res.render('profile-documents', {
        user: sessionUser,
        docs: [],
        error: 'Could not load your profile.',
      });
    }

    const docsSql = `
      SELECT * FROM documents
      WHERE user_id = ?
      ORDER BY uploaded_at DESC
    `;

    db.all(docsSql, [sessionUser.id], (err2, docs) => {
      if (err2) {
        console.error(err2);
        return res.render('profile-documents', {
          user: fullUser,
          docs: [],
          error: 'Could not load documents.',
        });
      }

      res.render('profile-documents', {
        user: fullUser,
        docs,
        error: null,
      });
    });
  });
});

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

// ----------------------------------------------------
// Manager: attendance overview
// ----------------------------------------------------
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

// ----------------------------------------------------
// Logout
// ----------------------------------------------------
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// ----------------------------------------------------
// Start server
// ----------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
