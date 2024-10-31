const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../models/User');
const router = express.Router();

const authMiddleware = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    console.log('Authorization header missing');
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  const token = authHeader.replace('Bearer ', '');
  console.log('Token:', token);
  try {
    const decoded = jwt.verify(token, 'secret');
    console.log('Decoded:', decoded);
    req.userId = decoded.id;
    next();
  } catch (error) {
    console.log('Unauthorized:', error.message);
    res.status(401).json({ message: 'Unauthorized' });
  }
};

// Configuración de transporte Nodemailer usando Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'lorenzoserrano.oscar@gmail.com', // Tu correo de Gmail
    pass: 'guxydrtdtvrtnfxq' // Contraseña de aplicación generada en Google
  }
});

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ email, password: hashedPassword });
  await newUser.save();
  res.json(newUser);
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: 'Usuario no encontrado' });
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });
  res.json({ token, user });
});

router.get('/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) {
    return res.status(404).json({ message: 'Usuario no encontrado' });
  }
  res.json(user);
});

// Endpoint para restablecer la contraseña (solicitud de token)
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  
  if (!user) {
    return res.status(400).json({ message: 'Usuario no encontrado' });
  }

  // Generar token de restablecimiento de contraseña
  const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '15m' });

  // Configuración del correo
  const mailOptions = {
    from: 'tuemail@gmail.com', // Tu correo de Gmail
    to: email,
    subject: 'Recuperación de contraseña',
    text: `Has solicitado restablecer tu contraseña. Utiliza el siguiente token para restablecerla: ${token}. 
Este token es válido por 15 minutos.`
  };

  // Enviar el correo con el token
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      return res.status(500).json({ message: 'Error al enviar el correo' });
    } else {
      console.log('Correo enviado: ' + info.response);
      res.json({ message: 'Token enviado para restablecer la contraseña' });
    }
  });
});

// Endpoint para restablecer la contraseña (cambio de contraseña)
router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, 'secret'); // Verificar el token con la misma clave
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    // Actualizar la contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Contraseña restablecida exitosamente' });
  } catch (error) {
    console.error('Error al restablecer la contraseña:', error.message);
    res.status(400).json({ message: 'Token inválido o expirado' });
  }
});

module.exports = router;
