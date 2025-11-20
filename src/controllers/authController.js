const bcrypt = require("bcrypt");
const config = require("../config/env");

const login = async (req, res) => {
    const { password } = req.body;
    if (!password || !config.admin.passwordHash) {
        return res.status(400).json({ success: false, message: 'Pedido inválido.' });
    }

    const match = await bcrypt.compare(password, config.admin.passwordHash);

    if (match) {
        req.session.isAdmin = true;
        req.session.save((err) => {
            if (err) {
                console.error('Erro ao salvar sessão:', err);
                return res.status(500).json({ success: false, message: 'Erro ao criar sessão.' });
            }
            if (config.isDevelopment) {
                console.log('Login bem-sucedido. Sessão criada:', req.sessionID);
            }
            return res.status(200).json({ success: true, message: 'Login bem-sucedido.' });
        });
    } else {
        res.status(401).json({ success: false, message: 'Senha incorreta.' });
    }
};

const logout = (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ message: 'Não foi possível fazer logout.' });
        res.status(200).json({ success: true, message: 'Logout bem-sucedido.' });
    });
};

const me = (req, res) => {
    res.status(200).json({
        email: 'admin@ecokambio.com',
        user_metadata: { full_name: 'Admin' }
    });
};

module.exports = { login, logout, me };
