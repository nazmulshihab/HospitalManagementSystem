const express = require("express");
const session = require("express-session");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { log } = require("console");
const { setTimeout } = require("timers");

dotenv.config(); 

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); 
app.use(cors());

app.use(session({
    secret: 'okay123',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } 
}));

function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next(); 
    } 
    else {
        return setTimeout(() => {
            res.sendFile(path.join(__dirname,'/public/HTML/','isAuth.html'));
        }, 800);       
    }
}

app.get('/check-session', (req, res) => {
    if (req.session.user) {
        
        return res.json({ user: { email: req.session.user.email, profilePic: req.session.user.profilePic,username: req.session.user.username } });
    } else {
        return res.json({ user: null });
    }
});

function authenticateUser(req, res, next) {
    const userId = req.cookies.userId;

    if (!userId) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    req.userId = userId;
    next();
}

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err.stack);
        return;
    }
    console.log("Connected to MySQL database.");
});

app.get('/', (req, res) => {
    return setTimeout(() => {
        res.sendFile(path.join(__dirname,'/public/HTML/','index.html'));
    }, 1000);
});

app.get('/api/doctors', (req, res) => {
    const branchId = req.query.branch;

    let query = `
SELECT 
    u.User_name,
    u.Email,
    d.DoctorID,
    d.img AS doctor_image,
    d.experiances,
    d.fee,
    s.S_name,
    GROUP_CONCAT(sc.scDays SEPARATOR ', ') AS scDays
FROM 
    Doctors d
JOIN 
    Users u 
ON 
    u.UserID = d.DoctorID
JOIN
    Doctor_Specialty ds 
ON 
    u.UserID = ds.DoctorID
JOIN
    Specialties s 
ON 
    s.SpID = ds.SpID
JOIN
    Schedules sc 
ON 
    sc.DoctorID = d.DoctorID`;

    // Add branch filter if branchId is provided
    if (branchId) {
        query += `
            JOIN 
                Branches b
            ON 
                d.BranchID = b.BranchID
            WHERE 
                b.BranchID = ? `;
    }

    query += `
    GROUP BY 
    u.User_name, u.Email, d.DoctorID, d.img, s.S_name`;
    const params = branchId ? [branchId] : [];
  
    db.query(query,params,(err, results) => {
      if (err) {
        console.error("Error fetching doctor information:", err);
        res.status(500).send("Internal server error");
      } else {
        console.log(results);
        res.json(results);  
      }
    });
});

app.get('/api/doctors/:doctorId', (req, res) => {
    const doctorId = req.params.doctorId;
      
const query = `
  SELECT 
    u.user_name, 
    d.img, 
    d.experiances,
    d.fee,
    GROUP_CONCAT(sc.scDays SEPARATOR ', ') AS scDays,
    s.s_name
FROM 
    Doctors d
JOIN 
    Users u 
ON 
    u.userID = d.doctorID 
JOIN 
    Schedules sc 
ON 
    d.doctorID = sc.doctorID 
JOIN
    Doctor_Specialty ds 
ON 
    u.userID = ds.DoctorID
JOIN
    Specialties s 
ON 
    s.SpID = ds.SpID
WHERE 
    d.doctorID = ?
GROUP BY 
    u.user_name, d.img, s.s_name;

`;
    db.query(query, [doctorId], (err, results) => {
        if (err) {
            console.error('Error fetching doctor details: ', err);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        if (results.length === 0) {
            res.status(404).json({ error: 'Doctor not found' });
            return;
        }
        res.json(results[0]);
    });
});

app.get('/doctor-profile', (req, res) => {
    res.sendFile(path.join(__dirname,'/public/HTML/','doctor-profile.html'));
});

app.get('/appointment', (req, res) => {
    return setTimeout(() => {
        res.sendFile(path.join(__dirname,'/public/HTML/','appointments.html'));
    }, 1000);
});

app.get('/test/catalog', (req, res) => {
    res.sendFile(path.join(__dirname,'/public/HTML/','test_catalog.html'));
});

app.get('/list',(req,res)=>{
    const query = `SELECT Test_name,Test_price FROM Diagnoses`;
    db.query(query,(err,result)=>{
        if (err) {
            console.error('Error fetching Lab Facilities:', err);
            return res.status(500).json({ error: 'Error fetching Lab Facilities.' });
        }
        res.json({testList: result});
        console.log(result);
    })

})

app.get('/diagnosis/history',isAuthenticated,(req,res)=>{
    const userID = req.session.user.userId;

    const query = `SELECT DiagnosisID,d.Test_name,Diagnosis_Date From DiagnosesHistory
    JOIN Diagnoses d ON d.TestID = DiagnosesHistory.TestID WHERE PatientID = ?`;

    db.query(query,[userID],(err,result)=>{
        if (err) {
            console.error('Error fetching diagnoses history:', err);
            return res.status(500).json({ error: 'Error fetching diagnoses history.' });
        }
        res.json({diagnosis: result});
        console.log(result);
    })
})

app.get('/get-stat', (req, res) => {
    const doctorID = req.session.user.userId;

    // Prepare queries
    const todayNum = `SELECT COUNT(AppointID) AS count FROM Appointments WHERE DoctorID = ? AND Status='Approved' AND DATE(A_date)=CURDATE()`;
    const monthNum = `SELECT COUNT(AppointID) AS count FROM Appointments WHERE DoctorID = ? AND Status='Approved' AND MONTH(A_date) = MONTH(CURDATE()) AND YEAR(A_date) = YEAR(CURDATE())`;
    const yearNum = `SELECT COUNT(AppointID) AS count FROM Appointments WHERE DoctorID = ? AND Status='Approved' AND YEAR(A_date) = YEAR(CURDATE())`;
    const totalNum = `SELECT COUNT(AppointID) AS count FROM Appointments WHERE DoctorID = ? AND Status='Approved'`;

    // Execute all queries asynchronously
    Promise.all([
        new Promise((resolve, reject) => {
            db.query(todayNum, [doctorID], (err, result) => {
                if (err) {
                    reject('Error fetching today\'s appointments.');
                } else {
                    resolve(result[0]?.count || 0); // Return the count or 0 if no result
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(monthNum, [doctorID], (err, result) => {
                if (err) {
                    reject('Error fetching this month\'s appointments.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(yearNum, [doctorID], (err, result) => {
                if (err) {
                    reject('Error fetching this year\'s appointments.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(totalNum, [doctorID], (err, result) => {
                if (err) {
                    reject('Error fetching total appointments.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        })
    ])
    .then(([ApToday, ApMonth, ApYear, ApTotal]) => {
        // Once all queries are completed, send a single response
        res.json({
            ApToday,
            ApMonth,
            ApYear,
            ApTotal
        });
    })
    .catch(error => {
        // Handle errors from any query
        console.error(error);
        res.status(500).json({ error: 'Error fetching appointment statistics.' });
    });
});

app.get('/admin-dashboard-stats', (req, res) => {
    // Prepare queries
    const totalUsersQuery = 'SELECT COUNT(*) AS count FROM Users';
    const totalPatientsQuery = 'SELECT COUNT(*) AS count FROM Users WHERE Role = "Patient"';
    const totalDoctorsQuery = 'SELECT COUNT(*) AS count FROM Users WHERE Role = "Doctor"';
    const availableDoctorsTodayQuery = `SELECT COUNT(DoctorID) AS count FROM Schedules  WHERE ScDays = DAYNAME(CURDATE())`;

    const todayAppointmentsQuery = `SELECT COUNT(*) AS count 
                                    FROM Appointments 
                                    WHERE Status = 'Approved' AND DATE(A_date) = CURDATE()`;
    const monthlyAppointmentsQuery = `SELECT COUNT(*) AS count 
                                      FROM Appointments 
                                      WHERE Status = 'Approved' 
                                        AND MONTH(A_date) = MONTH(CURDATE()) 
                                        AND YEAR(A_date) = YEAR(CURDATE())`;
    const yearlyAppointmentsQuery = `SELECT COUNT(*) AS count 
                                     FROM Appointments 
                                     WHERE Status = 'Approved' 
                                       AND YEAR(A_date) = YEAR(CURDATE())`;
    const totalAppointmentsQuery = 'SELECT COUNT(*) AS count FROM Appointments WHERE Status = "Approved"';

    Promise.all([
        new Promise((resolve, reject) => {
            db.query(totalUsersQuery, (err, result) => {
                if (err) {
                    reject('Error fetching total users.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(totalPatientsQuery, (err, result) => {
                if (err) {
                    reject('Error fetching total patients.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(totalDoctorsQuery, (err, result) => {
                if (err) {
                    reject('Error fetching total doctors.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(availableDoctorsTodayQuery, (err, result) => {
                if (err) {
                    reject('Error fetching available doctors today.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(todayAppointmentsQuery, (err, result) => {
                if (err) {
                    reject('Error fetching today\'s appointments.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(monthlyAppointmentsQuery, (err, result) => {
                if (err) {
                    reject('Error fetching this month\'s appointments.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(yearlyAppointmentsQuery, (err, result) => {
                if (err) {
                    reject('Error fetching this year\'s appointments.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.query(totalAppointmentsQuery, (err, result) => {
                if (err) {
                    reject('Error fetching total appointments.');
                } else {
                    resolve(result[0]?.count || 0);
                }
            });
        })
    ])
    .then(([totalUsers, totalPatients, totalDoctors, availableDoctorsToday, todayAppointments, monthlyAppointments, yearlyAppointments, totalAppointments]) => {
        res.json({
            totalUsers,
            totalPatients,
            totalDoctors,
            availableDoctorsToday,
            todayAppointments,
            monthlyAppointments,
            yearlyAppointments,
            totalAppointments
        });
    })
    .catch(error => {
        console.error(error);
        res.status(500).json({ error: 'Error fetching dashboard statistics.' });
    });
});


app.get('/history',(req,res)=>{
    const doctorId = req.session.user.userId;

    const query = `
        SELECT AppointID,Users.User_name, A_date,A_time,Status,SerialNo,Users.Gender,YEAR(CURDATE())-YEAR(Users.Birthyear) AS Age
        FROM Appointments
        JOIN Users
        ON Users.userID = Appointments.PatientID
        WHERE DoctorID = ?
    `;

    db.query(query,[doctorId],(err,result)=>{
        if (err) {
            console.error('Error fetching pending appointments:', err);
            return res.status(500).json({ error: 'Error fetching pending appointments.' });
        }
        res.json({history: result});
        console.log(result);
    })

})

app.get('/get-pending-appointments', isAuthenticated, (req, res) => {
    const doctorId = req.session.user.userId;
    console.log(doctorId);
    
    const query = `
        SELECT AppointID,Users.User_name,Users.Gender,YEAR(CURDATE())-YEAR(Users.Birthyear) AS Age,
        A_date,SerialNo
        FROM Appointments
        JOIN Users
        ON Users.userID = Appointments.PatientID
        WHERE DoctorID = ? AND Status = 'Pending'
    `;
    db.query(query, [doctorId], (err, results) => {
        if (err) {
            console.error('Error fetching pending appointments:', err);
            return res.status(500).json({ error: 'Error fetching pending appointments.' });
        }
        res.json({appointments: results});
        console.log(results);
    });
});

app.get('/appointments-today',isAuthenticated, (req,res)=>{
    const doctorid = req.session.user.userId;
    console.log(doctorid);
    const query = `SELECT AppointID,Users.User_name, A_date,A_time,Status,Users.Gender,YEAR(CURDATE())-YEAR(Users.Birthyear) AS Age
     FROM Appointments 
     JOIN Users ON Users.UserID = Appointments.PatientID
     WHERE DoctorID = ? AND Status = 'Approved'`;

    db.query(query,[doctorid],(err,results)=>{
        if(err)
        {
            console.error('Error fetching pending appointments:', err);
            return res.status(500).json({ error: 'Error fetching pending appointments.' });
        }

        res.json({today : results});
        console.log(results);
    })
})

app.get('/my-appointments',isAuthenticated, (req,res)=>{
    const patientid = req.session.user.userId;
    console.log(patientid);
    const query = `SELECT AppointID,Users.User_name, A_date, A_time, Status,SerialNO
     FROM Appointments 
     JOIN Users ON Users.UserID = Appointments.DoctorID
     WHERE PatientID = ? ORDER BY Status ASC`;

    db.query(query,[patientid],(err,results)=>{
        if(err)
        {
            console.error('Error fetching pending appointments:', err);
            return res.status(500).json({ error: 'Error fetching pending appointments.' });
        }

        res.json({myAppointments : results});
        console.log(results);
    })
})

app.get('/dashboard',isAuthenticated,(req,res)=>{
    const role = req.session.user.role;

    if(role === 'Patient'){
        res.redirect('/patient-dashboard');
}
    else if(role === 'Doctor'){
        res.redirect('/doctor-dashboard');
}
else if(req.session.user.role === 'Admin'){
    res.redirect('/admin');
}
})

app.get('/admin',isAuthenticated,(req,res)=>{
    setTimeout(() => {
        res.sendFile(path.join(__dirname, '/public/HTML/', 'admin-dash.html'));
    }, 1000);
})

app.get('/doctor-dashboard',isAuthenticated, (req, res) => {
    setTimeout(() => {
        res.sendFile(path.join(__dirname, '/public/HTML/', 'doctor-dash.html'));
    }, 1000);
});

app.get('/patient-dashboard',isAuthenticated, (req, res) => {
    setTimeout(() => {
        res.sendFile(path.join(__dirname, '/public/HTML/', 'patient-dash.html'));
    }, 1000);
});

app.post('/approve-appointment', isAuthenticated, (req, res) => {
    const appointmentId = req.body.appointmentId;
    const appointmentTime = req.body.appointmentTime;

    // Query to get appointment date and doctor ID from Appointments table
    const fetchAppointmentQuery = `
        SELECT A_date, DoctorID
        FROM Appointments
        WHERE AppointID = ?
    `;

    db.query(fetchAppointmentQuery, [appointmentId], (err, appointmentResult) => {
        if (err || appointmentResult.length === 0) {
            console.error('Error fetching appointment details:', err);
            return res.status(500).send('Error fetching appointment details.');
        }

        const { A_date, DoctorID } = appointmentResult[0];

        // Query to check slots and approved appointments
        const slotCheckQuery = `
            SELECT 
                s.Slots AS MaxSlots,
                COUNT(a.AppointID) AS ApprovedCount
            FROM 
                Schedules s
            LEFT JOIN 
                Appointments a 
            ON 
                s.DoctorID = a.DoctorID 
                AND s.ScDays = DAYNAME(?) 
                AND a.A_date = ? 
                AND a.Status = 'Approved'
            WHERE 
                s.DoctorID = ?
            GROUP BY 
                s.Slots
        `;

        db.query(slotCheckQuery, [A_date, A_date, DoctorID], (err, slotResult) => {
            if (err || slotResult.length === 0) {
                console.error('Error checking slots:', err);
                return res.status(500).send('Error checking slots.');
            }

            const { MaxSlots, ApprovedCount } = slotResult[0];

            if (ApprovedCount >= MaxSlots) {
                // Alert and stop further processing
                return res.status(400).send('<script>alert("No Available Slots.");</script>');
            }

            // Approve the appointment if slots are available
            const approveQuery = `
                UPDATE Appointments
                SET Status = 'Approved', A_Time = ?
                WHERE AppointID = ?
            `;

            db.query(approveQuery, [appointmentTime, appointmentId], (err, result) => {
                if (err) {
                    console.error('Error approving appointment:', err);
                    return res.status(500).send('Error approving appointment.');
                }

                res.redirect('/dashboard'); 
                console.log(result);
            });
        });
    });
});

app.post('/reject-appointment',(req,res)=>{
    const appointmentId = req.body.appointmentId;

    const query = `UPDATE Appointments SET Status = "Rejected" 
    WHERE AppointID = ? `;
    db.query(query,[appointmentId],(err,result)=>{
        if(err)
        {
            console.error('Error rejecting appointment:', err);
            return res.status(500).send('Error rejecting appointment.');
        }
        res.redirect('/dashboard');
    })
})

app.post('/doctorSpecialty',(req,res)=>{
    const { doctorID,spID,experiences} = req.body;

    const query1 = `INSERT INTO Doctor_Specialty (DoctorID,SpID) VALUES (?,?)`;
    db.query(query1,[doctorID,spID],(err,result)=>{
        if(err)
        {
            console.log('Error Occured')
        }

        const query2 = `UPDATE Doctors SET Experiances = ? WHERE DoctorID = ?`;
        db.query(query2,[experiences,doctorID],(err,result)=>{
        if(err)
        {
            console.log('Error Occured')
        }
        console.log("Successfully Updated into Doctors Table")
    })
    res.redirect('/dashboard');
    });

})

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/HTML/', 'create_account.html'));
});

app.get('/users',isAuthenticated,(req,res)=>{
    
    const query = `SELECT UserID,User_name,Gender,Birthyear,YEAR(CURDATE())-YEAR(Birthyear) AS Age,Email,img,Role FROM Users`;
    db.query(query,(err,result)=>{
        if(err)
        {
            console.error('Error fetching Users Data:', err);
            return res.status(500).send('Error fetching Users Data.');
        }
        res.json({userData: result});
        console.log(result);
    })
})

app.get('/patients',isAuthenticated,(req,res)=>{
    
    const query = `SELECT u.UserID, u.User_name,YEAR(CURDATE())-YEAR(Birthyear) AS Age,u.Gender, u.Birthyear, u.Email, u.Pass,u.img FROM Users u JOIN Patients p ON p.PatientID = u.UserID Where u.Role = "Patient"`;
    db.query(query,(err,result)=>{
        if(err)
        {
            console.error('Error fetching Users Data:', err);
            return res.status(500).send('Error fetching Users Data.');
        }
        res.json({patientData: result});
        console.log(result);
    })
});

app.get('/doctors',isAuthenticated,(req,res)=>{
    
    const query = `SELECT 
    u.UserID, 
    d.branchID,
    u.User_name, 
    u.Gender, 
    YEAR(CURDATE()) - YEAR(Birthyear) AS Age, 
    u.Birthyear, 
    u.Email, 
    u.Pass, 
    u.img, 
    d.Experiances, 
    d.fee, 
    COALESCE(sp.s_name, 'Not Set') AS s_name,
    COALESCE(GROUP_CONCAT(DISTINCT sc.scDays SEPARATOR ', '), 'Not Set') AS scDays,  
    COALESCE(GROUP_CONCAT(DISTINCT sc.slots SEPARATOR ', '), 'Not Set') AS slots
FROM Users u 
JOIN Doctors d ON d.DoctorID = u.UserID 
LEFT JOIN Doctor_Specialty ds ON d.DoctorID = ds.DoctorID  
LEFT JOIN Specialties sp ON sp.SpID = ds.SpID  
LEFT JOIN Schedules sc ON sc.DoctorID = d.DoctorID  
WHERE u.Role = "Doctor"
GROUP BY 
    u.UserID,d.branchID,u.User_name, u.Gender, u.Birthyear, u.Email, u.Pass, 
    u.img, d.Experiances, d.fee, sp.s_name;`;
    db.query(query,(err,result)=>{
        if(err)
        {
            console.error('Error fetching Users Data:', err);
            return res.status(500).send('Error fetching Users Data.');
        }
        res.json({doctorData: result});
        console.log(result);
    })
});

app.get('/doctors/today',isAuthenticated,(req,res)=>{
    const query = `SELECT u.UserID, u.User_name,u.Gender,sp.S_name FROM Users u JOIN Schedules s ON s.DoctorID = u.UserID JOIN Doctor_Specialty ds ON ds.DoctorID = u.UserID JOIN Specialties sp ON ds.spID = sp.spID
    Where DAYNAME(CURDATE())= s.ScDays;`;

    db.query(query,(err,result)=>{
        if(err)
        {
            console.error('Error fetching Users Data:', err);
            return res.status(500).send('Error fetching Users Data.');
        }
        res.json({availableDoctor: result});
        console.log(result);
    })
})

app.get('/appointments/today',isAuthenticated,(req,res)=>{
    const query = `SELECT 
    a.AppointID,
    u1.User_name AS PatientName,
    YEAR(CURDATE())-YEAR(u1.Birthyear) AS Age,
    u1.Gender AS Gender,
    u2.User_name AS DoctorName,
        a.A_time
    FROM 
        Appointments a
    JOIN 
        Users u1 ON a.PatientID = u1.UserID
    JOIN 
        Users u2 ON a.DoctorID = u2.UserID
    WHERE a.Status = 'Approved' AND a.A_date= CURDATE()
`;

    db.query(query,(err,result)=>{
        if(err)
        {
            console.error('Error fetching Users Data:', err);
            return res.status(500).send('Error fetching Users Data.');
        }
        res.json({appointmentsToday: result});
        console.log(result);
    })
})

app.get('/doctors/schedules',isAuthenticated,(req,res)=>{
    const query = `SELECT 
	u.userID,
    u.user_name, 
    u.Gender
    GROUP_CONCAT(sc.scDays SEPARATOR ', ') AS scDays
    FROM Doctors d
    JOIN Users u 
    ON u.userID = d.doctorID 
    JOIN Schedules sc 
    ON d.doctorID = sc.doctorID 
    GROUP BY u.userid,u.user_name`;

    db.query(query,(err,result)=>{
        if(err)
        {
            console.error('Error fetching Users Data:', err);
            return res.status(500).send('Error fetching Users Data.');
        }
        res.json({schedulesSet: result});
        console.log(result);
    })
})

app.get('/all/appointments',isAuthenticated,(req,res)=>{

    const query = `SELECT 
    a.AppointID,
    u1.User_name AS PatientName,
    YEAR(CURDATE())-YEAR(u1.Birthyear) AS Age,
    u1.Gender AS Gender,
    u2.User_name AS DoctorName,
    a.A_date,
    a.A_time
    FROM 
        Appointments a
    JOIN 
        Users u1 ON a.PatientID = u1.UserID
    JOIN 
        Users u2 ON a.DoctorID = u2.UserID
    WHERE a.Status = 'Approved'`;

    db.query(query,(err,result)=>{
        if(err)
        {
            console.error('Error fetching Users Data:', err);
            return res.status(500).send('Error fetching Users Data.');
        }
        res.json({allAp: result});
        console.log(result);
    })

    
})

// Login Connection
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname,'/public/HTML/','login.html'));
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Failed to destroy session' });
        }
    });
    res.clearCookie('connect.sid'); 
    setTimeout(()=>{
        res.redirect('/login'); 
    },500);
    console.log("Logged Out");
});

app.get('/invalid',(req,res)=>{
    setTimeout(() => {
        res.sendFile(path.join(__dirname, '/public/HTML/', 'notMatched.html'));
    }, 200);
})

app.post('/register', async (req, res) => {
    const { name, birthyear, gender, role, email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        //return res.status(400).json({ message: 'Password does not match' });
        setTimeout(() => {
            res.sendFile(path.join(__dirname, '/public/HTML/', 'confirmPass.html'));
        }, 200);
    }

    try {
        // Hashing the password
        const hashedPassword = crypto.createHash('sha224').update(password).digest('hex');

        // Insert user into Users table
        const query = 'INSERT INTO Users (User_name, Birthyear, Gender, Email, Pass,Role) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(query, [name, birthyear, gender, email, hashedPassword,role], (err, result) => {
            if (err) {
                console.log(err);
                return res.status(500).json({ message: 'Error creating user' });
            }

            // Get the user ID
            const userId = result.insertId;

            let insertRoleQuery;
            if (role === 'Patient') {
                insertRoleQuery = `
                    INSERT INTO Patients (PatientID) 
                    SELECT ? FROM DUAL 
                    WHERE NOT EXISTS (SELECT 1 FROM Patients WHERE PatientID = ?)
                `;
                db.query(insertRoleQuery, [userId, userId], (err, result) => {
                    if (err) {
                        console.error('Error inserting patient:', err);
                        return res.status(500).send('Error inserting patient data.');
                    }
                    console.log("Patient inserted successfully");
    
                    // Send the response after both operations complete
                    setTimeout(() => {
                        res.sendFile(path.join(__dirname, '/public/HTML/', 'registered.html'));
                    }, 1500);
                });
            } else{
                insertRoleQuery = `
                    INSERT INTO Doctors (DoctorID) 
                    SELECT ? FROM DUAL 
                    WHERE NOT EXISTS (SELECT 1 FROM Doctors WHERE DoctorID = ?)
                `;
                db.query(insertRoleQuery, [userId, userId], (err, result) => {
                    if (err) {
                        console.error('Error inserting patient:', err);
                        return res.status(500).send('Error inserting patient data.');
                    }
                    console.log("Doctor inserted successfully");
    
                    // Send the response after both operations complete
                    setTimeout(() => {
                        res.sendFile(path.join(__dirname, '/public/HTML/', 'registered.html'));
                    }, 1500);
                });
            }

            // Insert patient into Patients table
            // const insertPatient = `
            //     INSERT INTO Patients (PatientID) 
            //     SELECT ? 
            //     FROM DUAL
            //     WHERE NOT EXISTS (
            //         SELECT 1 FROM Patients WHERE PatientID = ?
            //     )
            // `;
            // db.query(insertPatient, [userId, userId], (err, result) => {
            //     if (err) {
            //         console.error('Error inserting patient:', err);
            //         return res.status(500).send('Error inserting patient data.');
            //     }
            //     console.log("Patient inserted successfully");

            //     // Send the response after both operations complete
            //     setTimeout(() => {
            //         res.sendFile(path.join(__dirname, '/public/HTML/', 'registered.html'));
            //     }, 1500);
            // });
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: 'Error hashing password' });
    }

    console.log({ password, confirmPassword });
});

app.post('/login', async (req, res) => {
    const { email, pass } = req.body;

    console.log('Request Body:', req.body);
    console.log({ email, pass });

    const query = 'SELECT * FROM Users WHERE Email = ?';
    db.query(query, [email], async (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (result.length === 0) {
            return setTimeout(() => {
                res.sendFile(path.join(__dirname, '/public/HTML/', 'notMatched.html'));
            }, 1500);
        }

        const user = result[0];

        const isPasswordCorrect = crypto.createHash('sha224').update(pass).digest('hex') === user.Pass;

        if (isPasswordCorrect) {
            // Session management
            req.session.user = { 
                email: user.Email, 
                userId: user.UserID,
                username: user.User_name,
                profilePic: user.img,
                role: user.Role
            };

            if(req.session.user.role === 'Patient'){
                    res.redirect('/patient-dashboard');
            }
            else if(req.session.user.role === 'Doctor'){
                    res.redirect('/doctor-dashboard');
            }
            else if(req.session.user.role === 'Admin'){
                res.redirect('/admin');
            }
                console.log(`${email} logged in`);
        } 
        else {
            res.redirect('/invalid');
        }
        console.log({ email, pass });
    });
});

app.get('/request-appointment', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, '/public/HTML/', 'patient-dash.html'));
});

app.post('/request-appointment', isAuthenticated, (req, res) => {
    const appointmentDay = req.body['appointment-day']; 
    const patientId = req.session.user.userId; 
    const doctorId = req.query.doctorId;

    // Ensure required fields are present
    if (!appointmentDay || !patientId || !doctorId) {
        console.log(appointmentDay);
        console.log(patientId);
        console.log(doctorId);
        return res.status(400).send('Missing required data.');
    }

    const appointmentDate = new Date(appointmentDay).toISOString().split('T')[0];;

    // Query to determine the next serial number for the doctor on the same date
    const serialNumberQuery = `
        SELECT IFNULL(MAX(SerialNo), 0) + 1 AS SerialNo
        FROM Appointments
        WHERE DoctorID = ? AND A_date = ?
    `;

    db.query(serialNumberQuery, [doctorId, appointmentDate], (err, result) => {
        if (err) {
            console.error('Error fetching serial number:', err);
            return res.status(500).send('Error processing appointment request.');
        }

        const serialNumber = result[0].SerialNo;

        const query = `
            INSERT INTO Appointments (A_date, Status, PatientID, DoctorID, SerialNo) 
            VALUES (?, 'Pending', ?, ?, ?)
        `;

        const values = [appointmentDate, patientId, doctorId, serialNumber];
        db.query(query, values, (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                                 return setTimeout(()=>{
                                     res.status(400).sendFile(path.join(__dirname, '/public/HTML/', 'multipleAp.html'));
                                 },1000)}
                console.error('Error inserting appointment:', err);
                return res.status(500).send('Error processing appointment request.');
            }
            setTimeout(() => {
                res.sendFile(path.join(__dirname, '/public/HTML/', 'successfulAp.html'));
            }, 1500);
        });
    });
});


const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});