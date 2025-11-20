const bcrypt = require('bcrypt');

// Gera hash para a senha especificada
const password = 'pp9898time';
const saltRounds = 10;

console.log('\n🔐 Gerando hash para a senha...\n');

bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
        console.error('❌ Erro ao gerar hash:', err);
        process.exit(1);
    }

    console.log('✅ Hash gerado com sucesso!\n');
    console.log('────────────────────────────────────────────────────────────');
    console.log('ADMIN_PASSWORD_HASH=' + hash);
    console.log('────────────────────────────────────────────────────────────');
    console.log('\nCopie a linha acima e atualize no seu arquivo .env\n');

    process.exit(0);
});
