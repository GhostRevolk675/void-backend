const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API raiz
app.get('/', (req, res) => {
  res.json({
    name: 'VOID API',
    version: '1.0.0',
    message: 'Backend funcionando!'
  });
});

// Rota de registro
app.post('/api/auth/register', (req, res) => {
  console.log('📝 Registro:', req.body);
  res.json({
    user: {
      id: '1',
      username: req.body.username || 'GhostRevo',
      created_at: new Date().toISOString()
    },
    access_token: 'fake-access-token-123',
    refresh_token: 'fake-refresh-token-456'
  });
});

// Rota de login
app.post('/api/auth/login', (req, res) => {
  console.log('🔐 Login:', req.body);
  res.json({
    user: {
      id: '1',
      username: req.body.username || 'GhostRevo',
      last_seen: new Date().toISOString()
    },
    access_token: 'fake-access-token-123',
    refresh_token: 'fake-refresh-token-456'
  });
});

// Rota de conversas
app.get('/api/conversations', (req, res) => {
  console.log('💬 Buscando conversas');
  res.json({
    conversations: []
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Backend rodando em http://0.0.0.0:${PORT}`);
});
