const bcrypt = require('bcrypt');
const readline = require('readline');

// Este script ajuda a criar um hash seguro para a sua senha de administrador.
// Uso: node hash-password.js

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question('Digite a senha de administrador que deseja usar: ', (password) => {
  if (!password || password.trim().length === 0) {
    console.error('\n[ERRO] A senha não pode estar em branco.');
    rl.close();
    process.exit(1);
  }

  const saltRounds = 10; // Fator de custo para o hash

  console.log('\nA gerar o hash da senha... (isto pode demorar um pouco)');

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('\nOcorreu um erro ao gerar o hash:', err);
    } else {
      console.log('\n✅ Senha hasheada com sucesso!');
      console.log('\nCopie o hash abaixo e cole-o na sua variável de ambiente `ADMIN_PASSWORD_HASH` (geralmente num ficheiro `.env`).');
      console.log('\n----------------------------------------------------');
      console.log('Hash:', hash);
      console.log('----------------------------------------------------');
    }
    rl.close();
  });
});

rl.on('close', () => {
  process.exit(0);
});
