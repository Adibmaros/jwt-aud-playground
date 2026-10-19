import express from 'express';
import * as jose from 'jose';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia-kunci-jwt-super-aman-dan-panjang-banget-32char';
const JWT_ISSUER = process.env.JWT_ISSUER || 'auth-service';

const secretKey = new TextEncoder().encode(JWT_SECRET);

app.use(express.json());

// Enable CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Serve static UI
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'auth-service', timestamp: new Date().toISOString() });
});

/**
 * POST /api/auth/token
 * Body: { "username": "budi", "audience": "user-service" | "order-service" }
 */
app.post('/api/auth/token', async (req, res) => {
  try {
    const {
      username = 'budi_santoso',
      audience = 'user-service',
      expiresIn = '1h',
      issuer = JWT_ISSUER,
      role = 'member'
    } = req.body;

    const builder = new jose.SignJWT({
      sub: 'usr_10293847',
      username,
      role,
      email: `${username}@example.com`
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuer(issuer)
      .setAudience(audience) // Bisa string atau array ["user-service", "order-service"]
      .setIssuedAt();

    if (expiresIn === 'expired') {
      // Set waktu kedaluwarsa 1 jam yang lalu
      builder.setExpirationTime(Math.floor(Date.now() / 1000) - 3600);
    } else {
      builder.setExpirationTime(expiresIn);
    }

    const token = await builder.sign(secretKey);

    const decodedHeader = jose.decodeProtectedHeader(token);
    const decodedPayload = jose.decodeJwt(token);

    console.log(`[AuthService] Token diterbitkan untuk username="${username}", target audience="${audience}"`);

    return res.status(200).json({
      success: true,
      message: `Token berhasil diterbitkan khusus untuk [${audience}]`,
      targetAudience: audience,
      token,
      decoded: {
        header: decodedHeader,
        payload: decodedPayload
      }
    });
  } catch (error) {
    console.error('[AuthService] Error saat menerbitkan token:', error);
    return res.status(500).json({
      success: false,
      error: 'TokenGenerationError',
      message: error.message
    });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 [AuthService] Berjalan di port ${PORT} (http://localhost:${PORT})`);
});
