const bcrypt = require('bcrypt');
const readline = require('readline');
require('dotenv').config();

// Script para verificar se uma senha corresponde ao hash configurado
// Uso: node verify-password.js

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const storedHash = process.env.ADMIN_PASSWORD_HASH;

if (!storedHash) {
  console.error('\n❌ ERRO: ADMIN_PASSWORD_HASH não encontrado no arquivo .env');
  rl.close();
  process.exit(1);
}

console.log('\n🔐 Verificador de Senha Admin');
console.log('════════════════════════════════════════');

rl.question('\nDigite a senha para verificar: ', async (password) => {
  if (!password || password.trim().length === 0) {
    console.error('\n❌ A senha não pode estar em branco.');
    rl.close();
    process.exit(1);
  }

  try {
    const match = await bcrypt.compare(password, storedHash);
    
    if (match) {
      console.log('\n✅ SENHA CORRETA! Esta senha funciona para fazer login.');
    } else {
      console.log('\n❌ SENHA INCORRETA! Esta não é a senha configurada.');
    }
  } catch (err) {
    console.error('\n❌ Erro ao verificar senha:', err);
  }
  
  rl.close();
});

rl.on('close', () => {
  process.exit(0);
});
