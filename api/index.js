const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  } else {
    admin.initializeApp({
      credential: admin.credential.applicationDefault()
    });
  }
}

const db = admin.firestore();
const app = express();

// Raw body parser for Cashfree webhook signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-admin-secret');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Authentication Middleware
const verifyAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: Missing or invalid token format' });
    }
    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token', details: error.message });
  }
};

// Admin Authentication Middleware
const verifyAdmin = (req, res, next) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (process.env.ADMIN_SECRET_KEY && adminSecret !== process.env.ADMIN_SECRET_KEY) {
    return res.status(403).json({ error: 'Forbidden: Invalid Admin Secret' });
  }
  next();
};

// --------------------------------------------------
// AUTHENTICATION & USER MANAGEMENT
// --------------------------------------------------

app.post('/auth/signup', verifyAuth, async (req, res) => {
  const { username, email, referralCode } = req.body;
  const uid = req.user.uid;

  if (!username || !email) {
    return res.status(400).json({ error: 'Username and email are required' });
  }

  const userRef = db.collection('users').doc(uid);

  try {
    const result = await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (userDoc.exists) {
        return { status: 'EXISTS', user: userDoc.data() };
      }

      const generatedReferralCode = Math.random().toString(36).substring(2, 8).toUpperCase();
      const newUser = {
        username: username,
        email: email,
        wallet: 0,
        totalXP: 0,
        joinedMatches: [],
        referralCode: generatedReferralCode,
        referredBy: referralCode || null,
        matchesPlayed: 0,
        totalKills: 0,
        dailyStreak: 0,
        isVIP: false,
        lastDailyReward: null,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      };

      transaction.set(userRef, newUser);
      return { status: 'CREATED', user: newUser };
    });

    return res.status(200).json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------
// PAYMENT GATEWAY (CASHFREE)
// --------------------------------------------------

app.post('/wallet/createOrder', verifyAuth, async (req, res) => {
  const { amount } = req.body;
  const uid = req.user.uid;

  if (!amount || typeof amount !== 'number' || amount <= 0) {
    return res.status(400).json({ error: 'A valid positive amount is required' });
  }

  const orderId = `ORDER_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  try {
    const userDoc = await db.collection('users').doc(uid).get();
    const userData = userDoc.exists ? userDoc.data() : {};

    const baseUrl = process.env.CASHFREE_ENV === 'PRODUCTION'
      ? 'https://api.cashfree.com/pg'
      : 'https://sandbox.cashfree.com/pg';

    const response = await fetch(`${baseUrl}/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-version': '2023-08-01',
        'x-client-id': process.env.CASHFREE_APP_ID || '',
        'x-client-secret': process.env.CASHFREE_SECRET_KEY || ''
      },
      body: JSON.stringify({
        order_id: orderId,
        order_amount: amount,
        order_currency: 'INR',
        customer_details: {
          customer_id: uid,
          customer_email: userData.email || 'user@example.com',
          customer_phone: '9999999999'
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(400).json({ error: 'Cashfree order creation failed', details: data });
    }

    const txRef = db.collection('transactions').doc(orderId);
    await txRef.set({
      userId: uid,
      type: 'DEPOSIT',
      amount: amount,
      status: 'PENDING',
      orderId: orderId,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.status(200).json({
      orderId: orderId,
      paymentSessionId: data.payment_session_id,
      orderData: data
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/webhook/cashfree', async (req, res) => {
  try {
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    const secretKey = process.env.CASHFREE_SECRET_KEY || '';

    if (secretKey && signature && timestamp) {
      const rawBody = req.rawBody || JSON.stringify(req.body);
      const generatedSignature = crypto
        .createHmac('sha256', secretKey)
        .update(timestamp + rawBody)
        .digest('base64');

      if (signature !== generatedSignature) {
        return res.status(400).json({ error: 'Invalid webhook signature' });
      }
    }

    const payload = req.body;
    const data = payload.data || {};
    const orderId = data.order?.order_id || payload.order_id;
    const paymentStatus = data.payment?.payment_status || payload.payment_status;
    const orderAmount = data.order?.order_amount || payload.order_amount;

    if (!orderId) {
      return res.status(400).json({ error: 'Missing orderId in webhook payload' });
    }

    const txRef = db.collection('transactions').doc(orderId);

    await db.runTransaction(async (transaction) => {
      const txDoc = await transaction.get(txRef);
      if (!txDoc.exists) {
        throw new Error('Transaction not found');
      }

      const txData = txDoc.data();
      if (txData.status !== 'PENDING') {
        return; // Idempotent handling: already finalized
      }

      if (paymentStatus === 'SUCCESS') {
        const userRef = db.collection('users').doc(txData.userId);
        const userDoc = await transaction.get(userRef);
        if (userDoc.exists) {
          const currentWallet = userDoc.data().wallet || 0;
          transaction.update(userRef, {
            wallet: currentWallet + (orderAmount || txData.amount)
          });
        }
        transaction.update(txRef, {
          status: 'SUCCESS',
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      } else if (paymentStatus === 'FAILED' || paymentStatus === 'CANCELLED') {
        transaction.update(txRef, {
          status: 'FAILED',
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    });

    return res.status(200).json({ status: 'OK' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------
// MATCH SYSTEM
// --------------------------------------------------

app.post('/match/join', verifyAuth, async (req, res) => {
  const { matchId, gameUids } = req.body;
  const uid = req.user.uid;

  if (!matchId || !Array.isArray(gameUids) || ![1, 2, 4].includes(gameUids.length)) {
    return res.status(400).json({ error: 'Invalid payload. gameUids must be an array of size 1, 2, or 4.' });
  }

  const matchRef = db.collection('matches').doc(matchId);
  const userRef = db.collection('users').doc(uid);
  const teamRef = db.collection('matches').doc(matchId).collection('teams').doc(uid);
  const teamsCollectionRef = db.collection('matches').doc(matchId).collection('teams');

  try {
    await db.runTransaction(async (transaction) => {
      const matchDoc = await transaction.get(matchRef);
      if (!matchDoc.exists) {
        throw new Error('Match not found');
      }

      const matchData = matchDoc.data();
      if (matchData.status !== 'upcoming') {
        throw new Error('Match is not open for joining');
      }

      const currentJoinedCount = matchData.joinedCount || 0;
      if (currentJoinedCount + gameUids.length > matchData.maxPlayers) {
        throw new Error('Match is full');
      }

      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('User record not found');
      }

      const userData = userDoc.data();
      if ((userData.wallet || 0) < matchData.entryFee) {
        throw new Error('Insufficient wallet balance');
      }

      const existingTeamDoc = await transaction.get(teamRef);
      if (existingTeamDoc.exists) {
        throw new Error('User has already joined this match');
      }

      const existingTeamsSnapshot = await transaction.get(teamsCollectionRef);
      const registeredGameUids = new Set();
      existingTeamsSnapshot.forEach((doc) => {
        const teamData = doc.data();
        if (teamData.gameUids && Array.isArray(teamData.gameUids)) {
          teamData.gameUids.forEach((gId) => registeredGameUids.add(gId));
        }
      });

      for (const gId of gameUids) {
        if (registeredGameUids.has(gId)) {
          throw new Error(`Game UID '${gId}' is already registered in this match`);
        }
      }

      transaction.update(userRef, {
        wallet: userData.wallet - matchData.entryFee,
        joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
      });

      transaction.update(matchRef, {
        joinedCount: currentJoinedCount + gameUids.length
      });

      transaction.set(teamRef, {
        ownerUid: uid,
        ownerUsername: userData.username || '',
        gameUids: gameUids,
        joinedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: uid,
        type: 'MATCH_ENTRY',
        amount: matchData.entryFee,
        status: 'SUCCESS',
        matchId: matchId,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(200).json({ success: true, message: 'Joined match successfully' });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// --------------------------------------------------
// REWARDS & WITHDRAWALS
// --------------------------------------------------

app.post('/rewards/daily', verifyAuth, async (req, res) => {
  const uid = req.user.uid;
  const userRef = db.collection('users').doc(uid);
  const REWARD_AMOUNT = 10;
  const DAY_MS = 24 * 60 * 60 * 1000;
  const TWO_DAYS_MS = 48 * 60 * 60 * 1000;

  try {
    const result = await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('User not found');
      }

      const userData = userDoc.data();
      const now = Date.now();
      const lastRewardMs = userData.lastDailyReward ? userData.lastDailyReward.toMillis() : 0;

      if (now - lastRewardMs < DAY_MS) {
        throw new Error('Daily reward already claimed within 24 hours');
      }

      let streak = userData.dailyStreak || 0;
      if (now - lastRewardMs <= TWO_DAYS_MS) {
        streak += 1;
      } else {
        streak = 1;
      }

      const newWalletBalance = (userData.wallet || 0) + REWARD_AMOUNT;

      transaction.update(userRef, {
        wallet: newWalletBalance,
        dailyStreak: streak,
        lastDailyReward: admin.firestore.Timestamp.fromMillis(now)
      });

      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: uid,
        type: 'DAILY_REWARD',
        amount: REWARD_AMOUNT,
        status: 'SUCCESS',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });

      return { wallet: newWalletBalance, streak };
    });

    return res.status(200).json({
      success: true,
      reward: REWARD_AMOUNT,
      dailyStreak: result.streak,
      wallet: result.wallet
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

app.post('/wallet/withdraw', verifyAuth, async (req, res) => {
  const { amount, upiId } = req.body;
  const uid = req.user.uid;

  if (!amount || typeof amount !== 'number' || amount <= 0 || !upiId || typeof upiId !== 'string') {
    return res.status(400).json({ error: 'Valid positive amount and upiId are required' });
  }

  const userRef = db.collection('users').doc(uid);

  try {
    await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('User not found');
      }

      const userData = userDoc.data();
      if ((userData.wallet || 0) < amount) {
        throw new Error('Insufficient wallet balance');
      }

      transaction.update(userRef, {
        wallet: userData.wallet - amount
      });

      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: uid,
        type: 'WITHDRAWAL',
        amount: amount,
        upiId: upiId,
        status: 'PENDING',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(200).json({ success: true, message: 'Withdrawal requested successfully' });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// --------------------------------------------------
// ADMIN & RESULT DISTRIBUTION
// --------------------------------------------------

app.post('/admin/match/distribute', verifyAdmin, async (req, res) => {
  const { matchId, gameUid, rank, kills } = req.body;

  if (!matchId || !gameUid || typeof rank !== 'number' || typeof kills !== 'number' || kills < 0 || rank < 1) {
    return res.status(400).json({ error: 'Valid matchId, gameUid, rank, and kills are required' });
  }

  const matchRef = db.collection('matches').doc(matchId);
  const teamsCollectionRef = db.collection('matches').doc(matchId).collection('teams');

  try {
    await db.runTransaction(async (transaction) => {
      const matchDoc = await transaction.get(matchRef);
      if (!matchDoc.exists) {
        throw new Error('Match not found');
      }

      const matchData = matchDoc.data();
      const distributedList = matchData.prizeDistributedList || [];

      if (distributedList.includes(gameUid)) {
        throw new Error(`Prize already distributed for gameUid: ${gameUid}`);
      }

      const teamsSnapshot = await transaction.get(teamsCollectionRef);
      let ownerUid = null;

      teamsSnapshot.forEach((doc) => {
        const teamData = doc.data();
        if (teamData.gameUids && Array.isArray(teamData.gameUids) && teamData.gameUids.includes(gameUid)) {
          ownerUid = teamData.ownerUid || doc.id;
        }
      });

      if (!ownerUid) {
        throw new Error(`No team found containing gameUid '${gameUid}'`);
      }

      const userRef = db.collection('users').doc(ownerUid);
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('Owner user document not found');
      }

      const perKillRate = matchData.perKillRate || 0;
      const rankPrizes = matchData.rankPrizes || {};
      const rankPrize = rankPrizes[rank] || rankPrizes[String(rank)] || 0;
      const prizeAmount = (kills * perKillRate) + rankPrize;

      const xpGain = (kills * 10) + (rank === 1 ? 100 : rank <= 3 ? 50 : 20);

      const userData = userDoc.data();

      transaction.update(userRef, {
        wallet: (userData.wallet || 0) + prizeAmount,
        totalXP: (userData.totalXP || 0) + xpGain,
        matchesPlayed: (userData.matchesPlayed || 0) + 1,
        totalKills: (userData.totalKills || 0) + kills
      });

      transaction.update(matchRef, {
        prizeDistributedList: admin.firestore.FieldValue.arrayUnion(gameUid)
      });

      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: ownerUid,
        type: 'PRIZE_PAYOUT',
        amount: prizeAmount,
        xpEarned: xpGain,
        matchId: matchId,
        gameUid: gameUid,
        status: 'SUCCESS',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(200).json({ success: true, message: 'Prize and XP distributed successfully' });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Esports backend running on port ${PORT}`);
});
const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  } else {
    admin.initializeApp({
      credential: admin.credential.applicationDefault()
    });
  }
}

const db = admin.firestore();
const app = express();

// Raw body parser for Cashfree webhook signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-admin-secret');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Authentication Middleware
const verifyAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: Missing or invalid token format' });
    }
    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token', details: error.message });
  }
};

// Admin Authentication Middleware
const verifyAdmin = (req, res, next) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (process.env.ADMIN_SECRET_KEY && adminSecret !== process.env.ADMIN_SECRET_KEY) {
    return res.status(403).json({ error: 'Forbidden: Invalid Admin Secret' });
  }
  next();
};

// --------------------------------------------------
// AUTHENTICATION & USER MANAGEMENT
// --------------------------------------------------

app.post('/auth/signup', verifyAuth, async (req, res) => {
  const { username, email, referralCode } = req.body;
  const uid = req.user.uid;

  if (!username || !email) {
    return res.status(400).json({ error: 'Username and email are required' });
  }

  const userRef = db.collection('users').doc(uid);

  try {
    const result = await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (userDoc.exists) {
        return { status: 'EXISTS', user: userDoc.data() };
      }

      const generatedReferralCode = Math.random().toString(36).substring(2, 8).toUpperCase();
      const newUser = {
        username: username,
        email: email,
        wallet: 0,
        totalXP: 0,
        joinedMatches: [],
        referralCode: generatedReferralCode,
        referredBy: referralCode || null,
        matchesPlayed: 0,
        totalKills: 0,
        dailyStreak: 0,
        isVIP: false,
        lastDailyReward: null,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      };

      transaction.set(userRef, newUser);
      return { status: 'CREATED', user: newUser };
    });

    return res.status(200).json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------
// PAYMENT GATEWAY (CASHFREE)
// --------------------------------------------------

app.post('/wallet/createOrder', verifyAuth, async (req, res) => {
  const { amount } = req.body;
  const uid = req.user.uid;

  if (!amount || typeof amount !== 'number' || amount <= 0) {
    return res.status(400).json({ error: 'A valid positive amount is required' });
  }

  const orderId = `ORDER_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  try {
    const userDoc = await db.collection('users').doc(uid).get();
    const userData = userDoc.exists ? userDoc.data() : {};

    const baseUrl = process.env.CASHFREE_ENV === 'PRODUCTION'
      ? 'https://api.cashfree.com/pg'
      : 'https://sandbox.cashfree.com/pg';

    const response = await fetch(`${baseUrl}/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-version': '2023-08-01',
        'x-client-id': process.env.CASHFREE_APP_ID || '',
        'x-client-secret': process.env.CASHFREE_SECRET_KEY || ''
      },
      body: JSON.stringify({
        order_id: orderId,
        order_amount: amount,
        order_currency: 'INR',
        customer_details: {
          customer_id: uid,
          customer_email: userData.email || 'user@example.com',
          customer_phone: '9999999999'
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(400).json({ error: 'Cashfree order creation failed', details: data });
    }

    const txRef = db.collection('transactions').doc(orderId);
    await txRef.set({
      userId: uid,
      type: 'DEPOSIT',
      amount: amount,
      status: 'PENDING',
      orderId: orderId,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.status(200).json({
      orderId: orderId,
      paymentSessionId: data.payment_session_id,
      orderData: data
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/webhook/cashfree', async (req, res) => {
  try {
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    const secretKey = process.env.CASHFREE_SECRET_KEY || '';

    if (secretKey && signature && timestamp) {
      const rawBody = req.rawBody || JSON.stringify(req.body);
      const generatedSignature = crypto
        .createHmac('sha256', secretKey)
        .update(timestamp + rawBody)
        .digest('base64');

      if (signature !== generatedSignature) {
        return res.status(400).json({ error: 'Invalid webhook signature' });
      }
    }

    const payload = req.body;
    const data = payload.data || {};
    const orderId = data.order?.order_id || payload.order_id;
    const paymentStatus = data.payment?.payment_status || payload.payment_status;
    const orderAmount = data.order?.order_amount || payload.order_amount;

    if (!orderId) {
      return res.status(400).json({ error: 'Missing orderId in webhook payload' });
    }

    const txRef = db.collection('transactions').doc(orderId);

    await db.runTransaction(async (transaction) => {
      const txDoc = await transaction.get(txRef);
      if (!txDoc.exists) {
        throw new Error('Transaction not found');
      }

      const txData = txDoc.data();
      if (txData.status !== 'PENDING') {
        return; // Idempotent handling: already finalized
      }

      if (paymentStatus === 'SUCCESS') {
        const userRef = db.collection('users').doc(txData.userId);
        const userDoc = await transaction.get(userRef);
        if (userDoc.exists) {
          const currentWallet = userDoc.data().wallet || 0;
          transaction.update(userRef, {
            wallet: currentWallet + (orderAmount || txData.amount)
          });
        }
        transaction.update(txRef, {
          status: 'SUCCESS',
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      } else if (paymentStatus === 'FAILED' || paymentStatus === 'CANCELLED') {
        transaction.update(txRef, {
          status: 'FAILED',
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    });

    return res.status(200).json({ status: 'OK' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------
// MATCH SYSTEM
// --------------------------------------------------

app.post('/match/join', verifyAuth, async (req, res) => {
  const { matchId, gameUids } = req.body;
  const uid = req.user.uid;

  if (!matchId || !Array.isArray(gameUids) || ![1, 2, 4].includes(gameUids.length)) {
    return res.status(400).json({ error: 'Invalid payload. gameUids must be an array of size 1, 2, or 4.' });
  }

  const matchRef = db.collection('matches').doc(matchId);
  const userRef = db.collection('users').doc(uid);
  const teamRef = db.collection('matches').doc(matchId).collection('teams').doc(uid);
  const teamsCollectionRef = db.collection('matches').doc(matchId).collection('teams');

  try {
    await db.runTransaction(async (transaction) => {
      const matchDoc = await transaction.get(matchRef);
      if (!matchDoc.exists) {
        throw new Error('Match not found');
      }

      const matchData = matchDoc.data();
      if (matchData.status !== 'upcoming') {
        throw new Error('Match is not open for joining');
      }

      const currentJoinedCount = matchData.joinedCount || 0;
      if (currentJoinedCount + gameUids.length > matchData.maxPlayers) {
        throw new Error('Match is full');
      }

      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('User record not found');
      }

      const userData = userDoc.data();
      if ((userData.wallet || 0) < matchData.entryFee) {
        throw new Error('Insufficient wallet balance');
      }

      const existingTeamDoc = await transaction.get(teamRef);
      if (existingTeamDoc.exists) {
        throw new Error('User has already joined this match');
      }

      const existingTeamsSnapshot = await transaction.get(teamsCollectionRef);
      const registeredGameUids = new Set();
      existingTeamsSnapshot.forEach((doc) => {
        const teamData = doc.data();
        if (teamData.gameUids && Array.isArray(teamData.gameUids)) {
          teamData.gameUids.forEach((gId) => registeredGameUids.add(gId));
        }
      });

      for (const gId of gameUids) {
        if (registeredGameUids.has(gId)) {
          throw new Error(`Game UID '${gId}' is already registered in this match`);
        }
      }

      transaction.update(userRef, {
        wallet: userData.wallet - matchData.entryFee,
        joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
      });

      transaction.update(matchRef, {
        joinedCount: currentJoinedCount + gameUids.length
      });

      transaction.set(teamRef, {
        ownerUid: uid,
        ownerUsername: userData.username || '',
        gameUids: gameUids,
        joinedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: uid,
        type: 'MATCH_ENTRY',
        amount: matchData.entryFee,
        status: 'SUCCESS',
        matchId: matchId,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(200).json({ success: true, message: 'Joined match successfully' });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// --------------------------------------------------
// REWARDS & WITHDRAWALS
// --------------------------------------------------

app.post('/rewards/daily', verifyAuth, async (req, res) => {
  const uid = req.user.uid;
  const userRef = db.collection('users').doc(uid);
  const REWARD_AMOUNT = 10;
  const DAY_MS = 24 * 60 * 60 * 1000;
  const TWO_DAYS_MS = 48 * 60 * 60 * 1000;

  try {
    const result = await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('User not found');
      }

      const userData = userDoc.data();
      const now = Date.now();
      const lastRewardMs = userData.lastDailyReward ? userData.lastDailyReward.toMillis() : 0;

      if (now - lastRewardMs < DAY_MS) {
        throw new Error('Daily reward already claimed within 24 hours');
      }

      let streak = userData.dailyStreak || 0;
      if (now - lastRewardMs <= TWO_DAYS_MS) {
        streak += 1;
      } else {
        streak = 1;
      }

      const newWalletBalance = (userData.wallet || 0) + REWARD_AMOUNT;

      transaction.update(userRef, {
        wallet: newWalletBalance,
        dailyStreak: streak,
        lastDailyReward: admin.firestore.Timestamp.fromMillis(now)
      });

      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: uid,
        type: 'DAILY_REWARD',
        amount: REWARD_AMOUNT,
        status: 'SUCCESS',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });

      return { wallet: newWalletBalance, streak };
    });

    return res.status(200).json({
      success: true,
      reward: REWARD_AMOUNT,
      dailyStreak: result.streak,
      wallet: result.wallet
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

app.post('/wallet/withdraw', verifyAuth, async (req, res) => {
  const { amount, upiId } = req.body;
  const uid = req.user.uid;

  if (!amount || typeof amount !== 'number' || amount <= 0 || !upiId || typeof upiId !== 'string') {
    return res.status(400).json({ error: 'Valid positive amount and upiId are required' });
  }

  const userRef = db.collection('users').doc(uid);

  try {
    await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('User not found');
      }

      const userData = userDoc.data();
      if ((userData.wallet || 0) < amount) {
        throw new Error('Insufficient wallet balance');
      }

      transaction.update(userRef, {
        wallet: userData.wallet - amount
      });

      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: uid,
        type: 'WITHDRAWAL',
        amount: amount,
        upiId: upiId,
        status: 'PENDING',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(200).json({ success: true, message: 'Withdrawal requested successfully' });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// --------------------------------------------------
// ADMIN & RESULT DISTRIBUTION
// --------------------------------------------------

app.post('/admin/match/distribute', verifyAdmin, async (req, res) => {
  const { matchId, gameUid, rank, kills } = req.body;

  if (!matchId || !gameUid || typeof rank !== 'number' || typeof kills !== 'number' || kills < 0 || rank < 1) {
    return res.status(400).json({ error: 'Valid matchId, gameUid, rank, and kills are required' });
  }

  const matchRef = db.collection('matches').doc(matchId);
  const teamsCollectionRef = db.collection('matches').doc(matchId).collection('teams');

  try {
    await db.runTransaction(async (transaction) => {
      const matchDoc = await transaction.get(matchRef);
      if (!matchDoc.exists) {
        throw new Error('Match not found');
      }

      const matchData = matchDoc.data();
      const distributedList = matchData.prizeDistributedList || [];

      if (distributedList.includes(gameUid)) {
        throw new Error(`Prize already distributed for gameUid: ${gameUid}`);
      }

      const teamsSnapshot = await transaction.get(teamsCollectionRef);
      let ownerUid = null;

      teamsSnapshot.forEach((doc) => {
        const teamData = doc.data();
        if (teamData.gameUids && Array.isArray(teamData.gameUids) && teamData.gameUids.includes(gameUid)) {
          ownerUid = teamData.ownerUid || doc.id;
        }
      });

      if (!ownerUid) {
        throw new Error(`No team found containing gameUid '${gameUid}'`);
      }

      const userRef = db.collection('users').doc(ownerUid);
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('Owner user document not found');
      }

      const perKillRate = matchData.perKillRate || 0;
      const rankPrizes = matchData.rankPrizes || {};
      const rankPrize = rankPrizes[rank] || rankPrizes[String(rank)] || 0;
      const prizeAmount = (kills * perKillRate) + rankPrize;

      const xpGain = (kills * 10) + (rank === 1 ? 100 : rank <= 3 ? 50 : 20);

      const userData = userDoc.data();

      transaction.update(userRef, {
        wallet: (userData.wallet || 0) + prizeAmount,
        totalXP: (userData.totalXP || 0) + xpGain,
        matchesPlayed: (userData.matchesPlayed || 0) + 1,
        totalKills: (userData.totalKills || 0) + kills
      });

      transaction.update(matchRef, {
        prizeDistributedList: admin.firestore.FieldValue.arrayUnion(gameUid)
      });

      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: ownerUid,
        type: 'PRIZE_PAYOUT',
        amount: prizeAmount,
        xpEarned: xpGain,
        matchId: matchId,
        gameUid: gameUid,
        status: 'SUCCESS',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    return res.status(200).json({ success: true, message: 'Prize and XP distributed successfully' });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Esports backend running on port ${PORT}`);
});
