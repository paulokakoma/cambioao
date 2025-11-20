const multer = require("multer");

// Configuração do Multer para upload de imagens em memória
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

module.exports = upload;
