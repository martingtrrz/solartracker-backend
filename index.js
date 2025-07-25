const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const validator = require('validator');

const app = express();
app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
  host: '82.197.82.133',
  user: 'u670852162_roman',
  password: 'SolarTracker2207',
  database: 'u670852162_solartracker',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool.getConnection((err, connection) => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err);
    return;
  }
  console.log('Conexión establecida con la base de datos');
  connection.release();
});

app.get('/', (req, res) => {
  res.send('API funcionando correctamente');
}); 

// --- Validaciones ---
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const isValidPassword = (password) => password.length >= 6;
const isValidName = (name) => /^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s'-]{2,100}$/.test(name);

// --- Login ---
app.post('/api/login', (req, res) => {
  const { correo, contrasena } = req.body;

  if (!correo || !contrasena || !isValidEmail(correo)) {
    return res.status(400).json({ error: 'Credenciales inválidas.' });
  }

  const query = 'SELECT idUsuario, nombre, correo, contrasena FROM usuario WHERE correo = ? LIMIT 1';
  pool.query(query, [correo], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas.' });
    }

    const user = results[0];
    try {
      const isMatch = await bcrypt.compare(contrasena, user.contrasena);
      if (!isMatch) return res.status(401).json({ error: 'Credenciales inválidas.' });

      res.json({
        idUsuario: user.idUsuario,
        nombre: user.nombre,
        correo: user.correo
      });
    } catch {
      res.status(500).json({ error: 'Error interno del servidor.' });
    }
  });
});

// --- Registro ---
app.post('/api/register', (req, res) => {
  const { nombre, correo, contrasena } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  }

  if (!isValidName(nombre)) {
    return res.status(400).json({ error: 'Nombre inválido.' });
  }

  if (!isValidEmail(correo)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }

  if (!isValidPassword(contrasena)) {
    return res.status(400).json({ error: 'Contraseña muy corta.' });
  }

  const sanitizedNombre = validator.escape(nombre);
  const checkUserQuery = 'SELECT idUsuario FROM usuario WHERE correo = ? LIMIT 1';

  pool.query(checkUserQuery, [correo], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Error del servidor.' });
    if (results.length > 0) return res.status(409).json({ error: 'Correo ya registrado.' });

    try {
      const hashedPassword = await bcrypt.hash(contrasena, 10);
      const insertUserQuery = 'INSERT INTO usuario (nombre, correo, contrasena) VALUES (?, ?, ?)';
      pool.query(insertUserQuery, [sanitizedNombre, correo, hashedPassword], (err) => {
        if (err) return res.status(500).json({ error: 'Error al registrar usuario.' });
        res.status(201).json({ message: 'Registro exitoso.' });
      });
    } catch {
      res.status(500).json({ error: 'Error interno del servidor.' });
    }
  });
});

// --- Actualizar perfil ---
app.post('/api/update-profile', (req, res) => {
  const { idUsuario, nombre, correo } = req.body;

  if (!idUsuario || !nombre || !correo || !isValidEmail(correo)) {
    return res.status(400).json({ error: 'Datos inválidos.' });
  }

  const query = 'UPDATE usuario SET nombre = ?, correo = ? WHERE idUsuario = ?';
  pool.query(query, [nombre, correo, idUsuario], (err, result) => {
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Correo ya en uso.' });
    } else if (err) {
      return res.status(500).json({ error: 'Error al actualizar perfil.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    res.json({ message: 'Perfil actualizado correctamente.' });
  });
});

// --- Cambiar contraseña ---
app.post('/api/change-password', (req, res) => {
  const { idUsuario, currentPassword, newPassword } = req.body;

  if (!idUsuario || !currentPassword || !newPassword || !isValidPassword(newPassword)) {
    return res.status(400).json({ error: 'Datos inválidos.' });
  }

  const query = 'SELECT contrasena FROM usuario WHERE idUsuario = ? LIMIT 1';
  pool.query(query, [idUsuario], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    const currentHash = results[0].contrasena;
    try {
      const isMatch = await bcrypt.compare(currentPassword, currentHash);
      if (!isMatch) return res.status(401).json({ error: 'Contraseña actual incorrecta.' });

      const newHashed = await bcrypt.hash(newPassword, 10);
      const updateQuery = 'UPDATE usuario SET contrasena = ? WHERE idUsuario = ?';
      pool.query(updateQuery, [newHashed, idUsuario], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error al actualizar contraseña.' });
        res.json({ message: 'Contraseña actualizada.' });
      });
    } catch {
      res.status(500).json({ error: 'Error del servidor.' });
    }
  });
});

// --- Consulta de panel por fecha ---
app.get('/api/panel-solar/by-date', (req, res) => {
  const { date } = req.query;

  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: 'Fecha inválida.' });
  }

  const query = `
    SELECT idPanel, energia, consumo, estado, fecha_hora
    FROM panelSolar
    WHERE DATE(fecha_hora) = ? AND TIME(fecha_hora) >= '06:00:00'
    ORDER BY fecha_hora ASC
  `;

  pool.query(query, [date], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener datos.' });
    if (results.length === 0) {
      return res.status(404).json({ message: 'Sin datos para esta fecha.' });
    }
    res.json(results);
  });
});

// --- Reportes semanales ---
app.get('/api/reportes-semanales', (req, res) => {
  const query = `
    SELECT fecha_inicio_semana, promedio_energia_diaria_kWh, promedio_consumo_diaria_kWh
    FROM reportes
    ORDER BY fecha_inicio_semana DESC
    LIMIT 7
  `;

  pool.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al consultar reportes.' });
    res.json(results);
  });
});

// --- Iniciar servidor ---
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});
