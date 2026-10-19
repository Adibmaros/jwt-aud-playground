import express from 'express';
import * as jose from 'jose';

const app = express();
const PORT = process.env.PORT || 3003;
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia-kunci-jwt-super-aman-dan-panjang-banget-32char';
const JWT_ISSUER = process.env.JWT_ISSUER || 'auth-service';
const EXPECTED_AUDIENCE = process.env.EXPECTED_AUDIENCE || 'order-service';

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

// Middleware Validasi JWT Khusus Order-Service
const requireOrderToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      service: 'order-service',
      error: 'TOKEN_MISSING',
      message: 'Header Authorization Bearer token wajib disertakan.'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verifikasi JWT: mengecek signature DAN claim aud === 'order-service'
    const { payload } = await jose.jwtVerify(token, secretKey, {
      issuer: JWT_ISSUER,
      audience: EXPECTED_AUDIENCE // << Validasi Audience di sini!
    });

    req.user = payload;
    next();
  } catch (err) {
    console.error(`[OrderService] Verifikasi token gagal:`, err.message);

    // KASUS UTAMA EKSPERIMEN: Signature valid tapi nilai claim 'aud' tidak cocok!
    if (err.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && err.claim === 'aud') {
      const decoded = jose.decodeJwt(token);
      return res.status(403).json({
        success: false,
        service: 'order-service',
        error: 'AUDIENCE_MISMATCH',
        message: `AKSES DITOLAK: Signature token VALID, tapi token ini bukan untuk '${EXPECTED_AUDIENCE}'!`,
        tokenAudience: decoded.aud,
        expectedAudience: EXPECTED_AUDIENCE,
        explanation: `Token ini diterbitkan khusus untuk aud=${JSON.stringify(decoded.aud)}. Walaupun ditandatangani oleh Auth Service yang sama, token ini tidak boleh dipakai di order-service.`
      });
    }

    if (err.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && err.claim === 'iss') {
      const decoded = jose.decodeJwt(token);
      return res.status(401).json({
        success: false,
        service: 'order-service',
        error: 'ISSUER_MISMATCH',
        message: `AKSES DITOLAK: Issuer '${decoded.iss}' tidak terpercaya. Service hanya menerima token dari '${JWT_ISSUER}'.`,
        tokenIssuer: decoded.iss,
        expectedIssuer: JWT_ISSUER
      });
    }

    if (err.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      return res.status(401).json({
        success: false,
        service: 'order-service',
        error: 'INVALID_SIGNATURE',
        message: 'Signature token tidak cocok atau rahasia kunci salah.'
      });
    }

    if (err.code === 'ERR_JWT_EXPIRED') {
      return res.status(401).json({
        success: false,
        service: 'order-service',
        error: 'TOKEN_EXPIRED',
        message: 'Token sudah kedaluwarsa.'
      });
    }

    return res.status(401).json({
      success: false,
      service: 'order-service',
      error: err.code || 'UNAUTHORIZED',
      message: err.message
    });
  }
};

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'order-service',
    expectedAudience: EXPECTED_AUDIENCE
  });
});

// Endpoint yang dilindungi
app.get('/api/orders', requireOrderToken, (req, res) => {
  res.json({
    success: true,
    service: 'order-service',
    message: '🎉 Akses BERHASIL! Token valid dan nilai audience (aud) cocok dengan order-service.',
    orders: [
      { id: 'ORD-2024-001', item: 'Mechanical Keyboard Wireless 75%', qty: 1, total: 850000, status: 'SHIPPED' },
      { id: 'ORD-2024-002', item: 'Gaming Mouse 26000 DPI', qty: 1, total: 450000, status: 'DELIVERED' }
    ],
    user: {
      userId: req.user.sub,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      tokenClaims: {
        iss: req.user.iss,
        aud: req.user.aud,
        exp: req.user.exp
      }
    }
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`📦 [OrderService] Berjalan di port ${PORT} (http://localhost:${PORT}) - Mengharuskan aud="${EXPECTED_AUDIENCE}"`);
});
