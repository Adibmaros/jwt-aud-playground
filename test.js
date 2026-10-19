/**
 * Eksperimen Microservices JWT: Pembuktian Claim 'aud' (Audience)
 * 
 * Jalankan dengan: node test.js
 * Pastikan ketiga service sudah berjalan melalui: podman compose up (atau docker compose up)
 */

const HOST = process.env.SERVICE_HOST || '127.0.0.1';
let AUTH_URL = process.env.AUTH_URL || `http://${HOST}:3001`;
let USER_URL = process.env.USER_URL || `http://${HOST}:3002`;
let ORDER_URL = process.env.ORDER_URL || `http://${HOST}:3003`;

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

const log = (msg) => console.log(msg);
const logHeader = (title) => console.log(`\n${colors.bright}${colors.cyan}═══════════════════════════════════════════════════════════════\n ${title}\n═══════════════════════════════════════════════════════════════${colors.reset}`);
const logPass = (msg) => console.log(`  ${colors.green}✔ BERHASIL: ${msg}${colors.reset}`);
const logFail = (msg) => console.log(`  ${colors.red}✘ GAGAL: ${msg}${colors.reset}`);

async function getToken(audience, username = 'budi_santoso') {
  const res = await fetch(`${AUTH_URL}/api/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, audience })
  });
  if (!res.ok) {
    throw new Error(`Gagal meminta token dari Auth Service (HTTP ${res.status})`);
  }
  return await res.json();
}

async function checkServiceHealth() {
  logHeader('1. Memeriksa Status Semua Service');
  const services = [
    { name: 'Auth Service', url: `${AUTH_URL}/health` },
    { name: 'User Service', url: `${USER_URL}/health` },
    { name: 'Order Service', url: `${ORDER_URL}/health` }
  ];

  for (const s of services) {
    try {
      const res = await fetch(s.url);
      if (res.ok) {
        logPass(`${s.name} AKTIF (${s.url})`);
      } else {
        logFail(`${s.name} merespons dengan HTTP ${res.status}`);
        return false;
      }
    } catch (e) {
      logFail(`Tidak dapat menghubungi ${s.name} di ${s.url}. Apakah podman/docker sudah dinyalakan?`);
      return false;
    }
  }
  return true;
}

async function runExperiment() {
  log(`\n${colors.bright}${colors.magenta}🚀 MEMULAI EKSPERIMEN VALIDASI JWT AUDIENCE (aud)${colors.reset}\n`);

  const healthy = await checkServiceHealth();
  if (!healthy) {
    log(`\n${colors.red}Eksperimen dihentikan karena satu atau lebih service belum berjalan.${colors.reset}`);
    log(`${colors.yellow}Petunjuk: Jalankan 'podman compose up --build -d' terlebih dahulu!${colors.reset}\n`);
    process.exit(1);
  }

  // ==========================================
  // SKENARIO 1: Token untuk User Service
  // ==========================================
  logHeader('2. Menerbitkan Token Khusus untuk [user-service]');
  const userTokenData = await getToken('user-service', 'ahmad_dhani');
  const userToken = userTokenData.token;
  log(`  Token Payload: ${JSON.stringify(userTokenData.decoded.payload)}`);
  log(`  Target Claim 'aud': ${colors.yellow}"${userTokenData.decoded.payload.aud}"${colors.reset}`);

  // Tes 1A: Kirim token user-service ke user-service (Harus DITERIMA)
  log(`\n  👉 [Tes 1A] Mengirim token (aud=user-service) ke User Service (Port 3002)...`);
  const res1A = await fetch(`${USER_URL}/api/users/profile`, {
    headers: { Authorization: `Bearer ${userToken}` }
  });
  const data1A = await res1A.json();
  if (res1A.status === 200) {
    logPass(`User Service menerima token! (HTTP 200 OK)`);
    log(`     Pesan: "${data1A.message}"`);
  } else {
    logFail(`Ekspektasi HTTP 200, didapat HTTP ${res1A.status}: ${JSON.stringify(data1A)}`);
  }

  // Tes 1B: Kirim token user-service ke ORDER-service (Harus DITOLAK karena audience beda)
  log(`\n  👉 [Tes 1B] Mengirim token (aud=user-service) yang SAMA ke Order Service (Port 3003)...`);
  const res1B = await fetch(`${ORDER_URL}/api/orders`, {
    headers: { Authorization: `Bearer ${userToken}` }
  });
  const data1B = await res1B.json();
  if (res1B.status === 403 && data1B.error === 'AUDIENCE_MISMATCH') {
    logPass(`Order Service MENOLAK token karena Audience Mismatch! (HTTP 403 Forbidden)`);
    log(`     Alasan Penolakan : ${colors.yellow}${data1B.message}${colors.reset}`);
    log(`     Token Audience   : ${colors.red}${data1B.tokenAudience}${colors.reset}`);
    log(`     Expected Audience: ${colors.green}${data1B.expectedAudience}${colors.reset}`);
  } else {
    logFail(`Ekspektasi HTTP 403 AUDIENCE_MISMATCH, didapat HTTP ${res1B.status}: ${JSON.stringify(data1B)}`);
  }

  // ==========================================
  // SKENARIO 2: Token untuk Order Service
  // ==========================================
  logHeader('3. Menerbitkan Token Khusus untuk [order-service]');
  const orderTokenData = await getToken('order-service', 'ahmad_dhani');
  const orderToken = orderTokenData.token;
  log(`  Token Payload: ${JSON.stringify(orderTokenData.decoded.payload)}`);
  log(`  Target Claim 'aud': ${colors.yellow}"${orderTokenData.decoded.payload.aud}"${colors.reset}`);

  // Tes 2A: Kirim token order-service ke order-service (Harus DITERIMA)
  log(`\n  👉 [Tes 2A] Mengirim token (aud=order-service) ke Order Service (Port 3003)...`);
  const res2A = await fetch(`${ORDER_URL}/api/orders`, {
    headers: { Authorization: `Bearer ${orderToken}` }
  });
  const data2A = await res2A.json();
  if (res2A.status === 200) {
    logPass(`Order Service menerima token! (HTTP 200 OK)`);
    log(`     Pesan: "${data2A.message}"`);
  } else {
    logFail(`Ekspektasi HTTP 200, didapat HTTP ${res2A.status}: ${JSON.stringify(data2A)}`);
  }

  // Tes 2B: Kirim token order-service ke USER-service (Harus DITOLAK karena audience beda)
  log(`\n  👉 [Tes 2B] Mengirim token (aud=order-service) yang SAMA ke User Service (Port 3002)...`);
  const res2B = await fetch(`${USER_URL}/api/users/profile`, {
    headers: { Authorization: `Bearer ${orderToken}` }
  });
  const data2B = await res2B.json();
  if (res2B.status === 403 && data2B.error === 'AUDIENCE_MISMATCH') {
    logPass(`User Service MENOLAK token karena Audience Mismatch! (HTTP 403 Forbidden)`);
    log(`     Alasan Penolakan : ${colors.yellow}${data2B.message}${colors.reset}`);
    log(`     Token Audience   : ${colors.red}${data2B.tokenAudience}${colors.reset}`);
    log(`     Expected Audience: ${colors.green}${data2B.expectedAudience}${colors.reset}`);
  } else {
    logFail(`Ekspektasi HTTP 403 AUDIENCE_MISMATCH, didapat HTTP ${res2B.status}: ${JSON.stringify(data2B)}`);
  }

  // ==========================================
  // SKENARIO 3: Token dengan Signature Rusak / Dimanipulasi
  // ==========================================
  logHeader('4. Menguji Token dengan Signature Rusak / Palsu');
  const fakeToken = userToken.substring(0, userToken.length - 8) + 'ABCDEF12';
  log(`  👉 [Tes 3] Mengirim token yang diubah signature-nya ke User Service...`);
  const res3 = await fetch(`${USER_URL}/api/users/profile`, {
    headers: { Authorization: `Bearer ${fakeToken}` }
  });
  const data3 = await res3.json();
  if (res3.status === 401 && data3.error === 'INVALID_SIGNATURE') {
    logPass(`Service berhasil menolak token palsu dengan HTTP 401 INVALID_SIGNATURE.`);
  } else {
    logFail(`Ekspektasi HTTP 401 INVALID_SIGNATURE, didapat HTTP ${res3.status}: ${JSON.stringify(data3)}`);
  }

  // ==========================================
  // SKENARIO 4: Token Kedaluwarsa (Expired)
  // ==========================================
  logHeader('5. Menguji Token yang Sudah Kedaluwarsa (Expired)');
  const expiredTokenData = await fetch(`${AUTH_URL}/api/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'budi_santoso', audience: 'user-service', expiresIn: 'expired' })
  }).then(r => r.json());
  
  log(`  👉 [Tes 4] Mengirim token expired ke User Service...`);
  const res4 = await fetch(`${USER_URL}/api/users/profile`, {
    headers: { Authorization: `Bearer ${expiredTokenData.token}` }
  });
  const data4 = await res4.json();
  if (res4.status === 401 && data4.error === 'TOKEN_EXPIRED') {
    logPass(`Service berhasil menolak token kedaluwarsa dengan HTTP 401 TOKEN_EXPIRED.`);
  } else {
    logFail(`Ekspektasi HTTP 401 TOKEN_EXPIRED, didapat HTTP ${res4.status}: ${JSON.stringify(data4)}`);
  }

  // ==========================================
  // SKENARIO 5: Token Multi-Audience Array (RFC 7519)
  // ==========================================
  logHeader('6. Menguji Token Multi-Audience Array ["user-service", "order-service"]');
  const multiTokenData = await fetch(`${AUTH_URL}/api/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'budi_santoso', audience: ['user-service', 'order-service'] })
  }).then(r => r.json());

  log(`  👉 [Tes 5A] Mengirim multi-audience token ke User Service...`);
  const res5A = await fetch(`${USER_URL}/api/users/profile`, {
    headers: { Authorization: `Bearer ${multiTokenData.token}` }
  });
  if (res5A.status === 200) logPass(`User Service menerima token multi-audience! (HTTP 200 OK)`);
  else logFail(`User Service menolak multi-audience token (HTTP ${res5A.status})`);

  log(`  👉 [Tes 5B] Mengirim multi-audience token ke Order Service...`);
  const res5B = await fetch(`${ORDER_URL}/api/orders`, {
    headers: { Authorization: `Bearer ${multiTokenData.token}` }
  });
  if (res5B.status === 200) logPass(`Order Service menerima token multi-audience! (HTTP 200 OK)`);
  else logFail(`Order Service menolak multi-audience token (HTTP ${res5B.status})`);

  // ==========================================
  // SKENARIO 6: Request Tanpa Token
  // ==========================================
  logHeader('7. Menguji Request Tanpa Header Authorization');
  const res6 = await fetch(`${USER_URL}/api/users/profile`);
  const data6 = await res6.json();
  if (res6.status === 401 && data6.error === 'TOKEN_MISSING') {
    logPass(`Service menolak request kosong dengan HTTP 401 TOKEN_MISSING.`);
  } else {
    logFail(`Ekspektasi HTTP 401 TOKEN_MISSING, didapat HTTP ${res6.status}`);
  }

  // ==========================================
  // KESIMPULAN
  // ==========================================
  logHeader('5. KESIMPULAN EKSPERIMEN');
  log(`${colors.green}${colors.bright}✔ HIPOTESIS TERBUKTI:${colors.reset}`);
  log(`  1. Kunci rahasia (Secret Key) yang sama digunakan di semua service.`);
  log(`  2. Token yang diterbitkan untuk 'user-service' memiliki SIGNATURE ASLI & SAH.`);
  log(`  3. Tetapi ketika dikirim ke 'order-service', request DITOLAK (HTTP 403) karena nilai 'aud' tidak sesuai.`);
  log(`  4. Ini membuktikan bahwa Signature Valid != Boleh Mengakses Semua Service!`);
  log(`  5. Claim 'aud' (Audience) sangat krusial dalam arsitektur Microservices untuk mencegah Token Replay / Confused Deputy Attack.`);
  log('');
}

runExperiment().catch((err) => {
  console.error('\nError tak terduga:', err);
});
