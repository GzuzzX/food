const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'happyfood',
  waitForConnections: true,
  connectionLimit: 10,
  enableKeepAlive: true,
  keepAliveInitialDelayMs: 0
});

// ✅ ตรวจสอบการเชื่อมต่อ Database
pool.getConnection((err, connection) => {
  if (err) {
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
      console.error('❌ Database connection was closed.');
    }
    if (err.code === 'PROTOCOL_ENQUEUE_AFTER_FATAL_ERROR') {
      console.error('❌ Database had a fatal error.');
    }
    if (err.code === 'PROTOCOL_ENQUEUE_AFTER_DESTROY') {
      console.error('❌ Database connection was destroyed.');
    }
    console.error('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Database connected successfully');
    if (connection) connection.release();
  }
});

module.exports = pool.promise();