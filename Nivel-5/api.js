const express = require('express');
const db = require('./db');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();

app.use(bodyParser.json());

const port = process.env.PORT || 3000;
const secretKey = 'P@%+~~=0[2YW59l@M+5ctb-;|Y4{z;1om1CuyN#n0t)pm0/yEC0"dn`wvg92D7A';

// Configuração do banco de dados
db.configure();

// Middleware para verificar o token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token não fornecido' });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Middleware para verificar o perfil do usuário
function authorizeAdmin(req, res, next) {
  getPerfil(req.user.usuario_id).then(perfil => {
    if (perfil !== 'admin') {
      return res.status(403).json({ message: 'Acesso negado: apenas administradores' });
    }
    next();
  }).catch(err => {
    res.status(500).json({ message: 'Erro interno do servidor' });
  });
}

// Endpoint para login do usuário
app.post('/api/auth/login', (req, res) => {
  const credentials = req.body;

  doLogin(credentials).then(userData => {
    if (userData) {
      const token = jwt.sign({ usuario_id: userData.id }, secretKey, { expiresIn: '30m' });
      res.json({ sessionid: token });
    } else {
      res.status(401).json({ message: 'Credenciais inválidas' });
    }
  }).catch(err => {
    res.status(500).json({ message: 'Erro interno do servidor' });
  });
});

// Endpoint para recuperação dos dados do usuário logado
app.get('/api/me', authenticateToken, (req, res) => {
  getUserById(req.user.usuario_id).then(userData => {
    res.status(200).json({ data: userData });
  }).catch(err => {
    res.status(500).json({ message: 'Erro interno do servidor' });
  });
});

// Endpoint para recuperação dos dados de todos os usuários cadastrados
app.get('/api/users', authenticateToken, authorizeAdmin, (req, res) => {
  getAllUsers().then(users => {
    res.status(200).json({ data: users });
  }).catch(err => {
    res.status(500).json({ message: 'Erro interno do servidor' });
  });
});

// Endpoint para recuperação dos contratos existentes
app.get('/api/contracts/:empresa/:inicio', authenticateToken, authorizeAdmin, async (req, res) => {
  const { empresa, inicio } = req.params;

  try {
    const result = await getContracts(empresa, inicio);
    if (result.length > 0) {
      res.status(200).json({ data: result });
    } else {
      res.status(404).json({ data: 'Dados não encontrados' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});