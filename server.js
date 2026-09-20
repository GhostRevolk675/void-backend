const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIO = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'void-secret-key-change-in-production';

// Initialize database tables
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        public_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      );

      CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        contact_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, contact_id)
      );

      CREATE TABLE IF NOT EXISTS conversations (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS conversation_participants (
        conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        PRIMARY KEY (conversation_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        message_type VARCHAR(20) DEFAULT 'text',
        ttl_seconds INTEGER,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read_at TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
      CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at);
    `);
    console.log('✅ Database initialized');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
}

initDatabase();

// Middleware para autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
}

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

// ========== AUTH ROUTES ==========

// Registro
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, public_key } = req.body;

    if (!username || !password || !public_key) {
      return res.status(400).json({ error: 'Campos obrigatórios faltando' });
    }

    // Verificar se usuário já existe
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Username já existe' });
    }

    // Hash da senha
    const passwordHash = await bcrypt.hash(password, 10);

    // Criar usuário
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, public_key)
       VALUES ($1, $2, $3)
       RETURNING id, username, public_key, created_at, is_active`,
      [username, passwordHash, public_key]
    );

    const user = result.rows[0];

    // Gerar token
    const accessToken = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      user: {
        id: user.id.toString(),
        username: user.username,
        public_key: user.public_key,
        created_at: user.created_at,
        is_active: user.is_active
      },
      access_token: accessToken,
      refresh_token: refreshToken
    });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro ao registrar usuário' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username e senha obrigatórios' });
    }

    // Buscar usuário
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const user = result.rows[0];

    // Verificar senha
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Atualizar last_seen
    await pool.query(
      'UPDATE users SET last_seen_at = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    // Gerar tokens
    const accessToken = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      user: {
        id: user.id.toString(),
        username: user.username,
        public_key: user.public_key,
        last_seen_at: new Date().toISOString(),
        is_active: user.is_active
      },
      access_token: accessToken,
      refresh_token: refreshToken
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro ao fazer login' });
  }
});

// ========== USER ROUTES ==========

// Buscar usuários (para adicionar contatos)
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    const result = await pool.query(
      `SELECT id, username, public_key, last_seen_at, is_active
       FROM users
       WHERE username ILIKE $1 AND id != $2
       LIMIT 20`,
      [`%${query}%`, req.user.id]
    );

    res.json({
      users: result.rows.map(u => ({
        id: u.id.toString(),
        username: u.username,
        public_key: u.public_key,
        last_seen_at: u.last_seen_at,
        is_active: u.is_active
      }))
    });
  } catch (error) {
    console.error('Erro na busca:', error);
    res.status(500).json({ error: 'Erro ao buscar usuários' });
  }
});

// ========== CONTACTS ROUTES ==========

// Adicionar contato
app.post('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const { contact_id } = req.body;

    await pool.query(
      'INSERT INTO contacts (user_id, contact_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, contact_id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Erro ao adicionar contato:', error);
    res.status(500).json({ error: 'Erro ao adicionar contato' });
  }
});

// Listar contatos
app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.public_key, u.last_seen_at, u.is_active
       FROM contacts c
       JOIN users u ON c.contact_id = u.id
       WHERE c.user_id = $1`,
      [req.user.id]
    );

    res.json({
      contacts: result.rows.map(u => ({
        id: u.id.toString(),
        username: u.username,
        public_key: u.public_key,
        last_seen_at: u.last_seen_at,
        is_active: u.is_active
      }))
    });
  } catch (error) {
    console.error('Erro ao listar contatos:', error);
    res.status(500).json({ error: 'Erro ao listar contatos' });
  }
});

// ========== CONVERSATIONS ROUTES ==========

// Criar ou buscar conversa
app.post('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const { recipient_id } = req.body;

    // Verificar se já existe conversa
    const existing = await pool.query(
      `SELECT c.id FROM conversations c
       JOIN conversation_participants cp1 ON c.id = cp1.conversation_id
       JOIN conversation_participants cp2 ON c.id = cp2.conversation_id
       WHERE cp1.user_id = $1 AND cp2.user_id = $2`,
      [req.user.id, recipient_id]
    );

    let conversationId;

    if (existing.rows.length > 0) {
      conversationId = existing.rows[0].id;
    } else {
      // Criar nova conversa
      const conv = await pool.query(
        'INSERT INTO conversations DEFAULT VALUES RETURNING id'
      );
      conversationId = conv.rows[0].id;

      // Adicionar participantes
      await pool.query(
        'INSERT INTO conversation_participants (conversation_id, user_id) VALUES ($1, $2), ($1, $3)',
        [conversationId, req.user.id, recipient_id]
      );
    }

    // Buscar dados da conversa
    const result = await pool.query(
      `SELECT u.id, u.username, u.public_key, u.last_seen_at
       FROM conversation_participants cp
       JOIN users u ON cp.user_id = u.id
       WHERE cp.conversation_id = $1 AND cp.user_id != $2`,
      [conversationId, req.user.id]
    );

    const otherUser = result.rows[0];

    res.json({
      conversation: {
        id: conversationId.toString(),
        recipient: {
          id: otherUser.id.toString(),
          username: otherUser.username,
          public_key: otherUser.public_key,
          last_seen_at: otherUser.last_seen_at
        }
      }
    });
  } catch (error) {
    console.error('Erro ao criar conversa:', error);
    res.status(500).json({ error: 'Erro ao criar conversa' });
  }
});

// Listar conversas
app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         c.id,
         u.id as recipient_id,
         u.username as recipient_username,
         u.public_key as recipient_public_key,
         u.last_seen_at as recipient_last_seen,
         u.is_active as recipient_is_active,
         (
           SELECT m.content
           FROM messages m
           WHERE m.conversation_id = c.id
           ORDER BY m.created_at DESC
           LIMIT 1
         ) as last_message,
         (
           SELECT m.created_at
           FROM messages m
           WHERE m.conversation_id = c.id
           ORDER BY m.created_at DESC
           LIMIT 1
         ) as last_message_at
       FROM conversations c
       JOIN conversation_participants cp ON c.id = cp.conversation_id AND cp.user_id = $1
       JOIN conversation_participants cp2 ON c.id = cp2.conversation_id AND cp2.user_id != $1
       JOIN users u ON cp2.user_id = u.id
       ORDER BY last_message_at DESC NULLS LAST`,
      [req.user.id]
    );

    res.json({
      conversations: result.rows.map(row => ({
        id: row.id.toString(),
        recipient: {
          id: row.recipient_id.toString(),
          username: row.recipient_username,
          public_key: row.recipient_public_key,
          last_seen_at: row.recipient_last_seen,
          is_active: row.recipient_is_active
        },
        last_message: row.last_message,
        last_message_at: row.last_message_at
      }))
    });
  } catch (error) {
    console.error('Erro ao listar conversas:', error);
    res.status(500).json({ error: 'Erro ao listar conversas' });
  }
});

// ========== MESSAGES ROUTES ==========

// Buscar mensagens de uma conversa
app.get('/api/messages/conversations/:conversationId', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { limit = 50 } = req.query;

    const result = await pool.query(
      `SELECT m.id, m.sender_id, m.content, m.message_type, m.ttl_seconds,
              m.expires_at, m.created_at, m.read_at
       FROM messages m
       WHERE m.conversation_id = $1
         AND (m.expires_at IS NULL OR m.expires_at > CURRENT_TIMESTAMP)
       ORDER BY m.created_at DESC
       LIMIT $2`,
      [conversationId, limit]
    );

    res.json({
      messages: result.rows.map(m => ({
        id: m.id.toString(),
        sender_id: m.sender_id.toString(),
        content: m.content,
        message_type: m.message_type,
        ttl_seconds: m.ttl_seconds,
        expires_at: m.expires_at,
        created_at: m.created_at,
        read_at: m.read_at
      })).reverse()
    });
  } catch (error) {
    console.error('Erro ao buscar mensagens:', error);
    res.status(500).json({ error: 'Erro ao buscar mensagens' });
  }
});

// Enviar mensagem
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { conversation_id, content, message_type = 'text', ttl_seconds } = req.body;

    let expiresAt = null;
    if (ttl_seconds && ttl_seconds > 0) {
      expiresAt = new Date(Date.now() + ttl_seconds * 1000);
    }

    const result = await pool.query(
      `INSERT INTO messages (conversation_id, sender_id, content, message_type, ttl_seconds, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [conversation_id, req.user.id, content, message_type, ttl_seconds, expiresAt]
    );

    const message = result.rows[0];

    // Emitir via WebSocket
    io.to(`conversation_${conversation_id}`).emit('new_message', {
      id: message.id.toString(),
      conversation_id: conversation_id,
      sender_id: message.sender_id.toString(),
      content: message.content,
      message_type: message.message_type,
      ttl_seconds: message.ttl_seconds,
      expires_at: message.expires_at,
      created_at: message.created_at
    });

    res.json({
      message: {
        id: message.id.toString(),
        conversation_id: conversation_id,
        sender_id: message.sender_id.toString(),
        content: message.content,
        message_type: message.message_type,
        ttl_seconds: message.ttl_seconds,
        expires_at: message.expires_at,
        created_at: message.created_at
      }
    });
  } catch (error) {
    console.error('Erro ao enviar mensagem:', error);
    res.status(500).json({ error: 'Erro ao enviar mensagem' });
  }
});

// ========== WEBSOCKET ==========

io.on('connection', (socket) => {
  console.log('🔌 Cliente conectado:', socket.id);

  socket.on('join_conversation', (conversationId) => {
    socket.join(`conversation_${conversationId}`);
    console.log(`👤 Socket ${socket.id} entrou na conversa ${conversationId}`);
  });

  socket.on('leave_conversation', (conversationId) => {
    socket.leave(`conversation_${conversationId}`);
  });

  socket.on('disconnect', () => {
    console.log('❌ Cliente desconectado:', socket.id);
  });
});

// Limpar mensagens expiradas a cada 5 segundos
setInterval(async () => {
  try {
    const result = await pool.query(
      `DELETE FROM messages
       WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP
       RETURNING id, conversation_id`
    );

    if (result.rowCount > 0) {
      console.log(`🗑️  ${result.rowCount} mensagens expiradas removidas`);

      // Notificar via WebSocket sobre cada mensagem expirada
      result.rows.forEach(row => {
        io.to(`conversation_${row.conversation_id}`).emit('message_expired', {
          message_id: row.id.toString(),
          conversation_id: row.conversation_id.toString()
        });
      });
    }
  } catch (error) {
    console.error('Erro ao limpar mensagens:', error);
  }
}, 5000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Backend rodando em http://0.0.0.0:${PORT}`);
});
