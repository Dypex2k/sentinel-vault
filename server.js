// server.js - sentinel-vault con protección de intentos masivos

const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const { actualizarPINenServidor } = require('./crypto');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(__dirname));

// Variables de control de seguridad
let intentosFallidos = 0;
const MAX_INTENTOS = 3;
let pinCongelado = false;

// Verificar y cargar hash válido desde archivo de configuración
function cargarConfig() {
  const config = JSON.parse(fs.readFileSync('server.json'));
  const now = Date.now();
  if (now > config.expiracion) {
    console.log("PIN expirado. Generando uno nuevo...");
    actualizarPINenServidor();
    return JSON.parse(fs.readFileSync('server.json'));
  }
  return config;
}

let config = cargarConfig();
let VALID_HASH = config.valid_hash;
let EXPIRATION = config.expiracion;

function logAccess(status, ip, pin) {
  const date = new Date().toISOString();
  const log = `[${date}] - ${status} | IP: ${ip} | PIN: ${pin}\n`;
  fs.appendFileSync('access.log', log);
}

function regenerarPINManual(motivo, ip, pin) {
  if (pinCongelado) {
    logAccess(`PIN BLOQUEADO - no se regeneró`, ip, pin);
    return;
  }

  if (intentosFallidos >= MAX_INTENTOS) {
    pinCongelado = true;
    console.log("⚠️ Límite de regeneraciones alcanzado. El PIN no se volverá a cambiar hasta que expire o se regenere manualmente.");
    logAccess(`PIN CONGELADO por exceso de intentos`, ip, pin);
    return;
  }

  actualizarPINenServidor();
  const nuevaConfig = JSON.parse(fs.readFileSync('server.json'));
  VALID_HASH = nuevaConfig.valid_hash;
  EXPIRATION = nuevaConfig.expiracion;
  intentosFallidos++;
  logAccess(`PIN FORZADO (${motivo})`, ip, pin);
}

// Endpoint de autenticación
app.post('/auth', (req, res) => {
  const pin = req.body.pin;
  const ip = req.ip || req.connection.remoteAddress;
  const hash = crypto.createHash('sha1').update(pin).digest('hex');

  const now = Date.now();
  if (now > EXPIRATION) {
    logAccess('PIN EXPIRED', ip, pin);
    regenerarPINManual("expiración", ip, pin);
    return res.json({ access: false, reason: "expired" });
  }

  if (hash === VALID_HASH) {
    logAccess('ACCESS GRANTED', ip, pin);
    intentosFallidos = 0;
    res.json({ access: true });
  } else {
    regenerarPINManual("intento inválido", ip, pin);
    res.json({ access: false });
  }
});

app.listen(PORT, () => {
  console.log(`Sentinel-Vault corriendo en http://localhost:${PORT}`);
});

