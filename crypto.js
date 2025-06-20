// crypto.js - módulo de cifrado para sentinel-vault (cliente y servidor)

const crypto = require('crypto');
const fs = require('fs');

// Generar hash SHA1 desde texto plano
function generarHashSHA1(pin) {
  return crypto.createHash('sha1').update(pin).digest('hex');
}

// Generar un nuevo PIN de 4 dígitos aleatorios
function generarNuevoPIN() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

// Crear hash + escribir en server.json + imprimir en terminal
function actualizarPINenServidor() {
  const nuevoPIN = generarNuevoPIN();
  const hash = generarHashSHA1(nuevoPIN);

  const config = {
    valid_hash: hash,
    expiracion: Date.now() + (2 * 24 * 60 * 60 * 1000) // +2 días en ms
  };

  fs.writeFileSync('server.json', JSON.stringify(config, null, 2));
  console.log("==============================");
  console.log("Nuevo PIN generado:", nuevoPIN);
  console.log("Hash guardado:", hash);
  console.log("Expira el:", new Date(config.expiracion).toString());
  console.log("==============================");
}

// Ejecutar si se llama desde terminal directamente
if (require.main === module) {
  actualizarPINenServidor();
}

module.exports = {
  generarNuevoPIN,
  generarHashSHA1,
  actualizarPINenServidor
};

