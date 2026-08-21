// =============================================
//  المتغيرات العامة والإعدادات
// =============================================

let walletHistory = [];
let currentMnemonic = '';
let currentAddress = '';
let currentCoin = 'ethereum';
let currentPrivateKey = '';

const coinNames = {
  ethereum: 'Ethereum (ETH)',
  bnb: 'BNB (BSC)',
  usdt: 'Tether (USDT)'
};

const coinExplorers = {
  ethereum: 'https://etherscan.io/address/',
  bnb: 'https://bscscan.com/address/',
  usdt: 'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7?a='
};

const coinSymbols = {
  ethereum: 'ETH',
  bnb: 'BNB',
  usdt: 'USDT'
};

const coinEmojis = {
  ethereum: '⟠',
  bnb: '🟡',
  usdt: '💵'
};

const providers = {
  ethereum: [
    'https://cloudflare-eth.com',
    'https://rpc.ankr.com/eth',
    'https://ethereum.publicnode.com'
  ],
  bnb: [
    'https://bsc-dataseed.binance.org/',
    'https://bsc-dataseed1.defibit.io/',
    'https://bsc-dataseed1.ninicoin.io/'
  ],
  usdt: [
    'https://cloudflare-eth.com',
    'https://rpc.ankr.com/eth',
    'https://ethereum.publicnode.com'
  ]
};

const USDT_ADDRESS = '0xdac17f958d2ee523a2206206994597c13d831ec7';

// =============================================
//  دالة SHA‑256 (تطبيق يدوي)
// =============================================

function sha256(message) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }

  const msg = unescape(encodeURIComponent(message));
  const msgLen = msg.length;
  const msgBits = [];

  for (let i = 0; i < msgLen; i++) {
    msgBits[i] = msg.charCodeAt(i);
  }

  const bitLen = msgLen * 8;
  msgBits.push(0x80);

  while ((msgBits.length * 8) % 512 !== 448) {
    msgBits.push(0x00);
  }

  for (let i = 0; i < 8; i++) {
    msgBits.push((bitLen >>> (56 - i * 8)) & 0xFF);
  }

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const words = [];
  for (let i = 0; i < msgBits.length; i += 4) {
    words.push(
      (msgBits[i] << 24) |
      (msgBits[i + 1] << 16) |
      (msgBits[i + 2] << 8) |
      msgBits[i + 3]
    );
  }

  for (let i = 0; i < words.length; i += 16) {
    const w = words.slice(i, i + 16);

    for (let j = 16; j < 64; j++) {
      const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
      const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
    }

    let [a, b, c, d] = H;
    let [e, f, g, h] = [H[4], H[5], H[6], H[7]];

    for (let j = 0; j < 64; j++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }

  let result = '';
  for (let i = 0; i < 8; i++) {
    result += ('00000000' + H[i].toString(16)).slice(-8);
  }
  return result;
}

// =============================================
//  دوال جلب الرصيد وعرضه
// =============================================

async function fetchBalance() {
  const pill = document.getElementById('balancePill');
  const coin = currentCoin || 'ethereum';
  const symbol = coinSymbols[coin] || 'ETH';
  const address = currentAddress;

  if (!address || address === '—' || address === '') {
    pill.textContent = '⚠️ No wallet';
    pill.className = 'balance-pill error';
    setStatus('⚠️ No wallet address available. Generate or import a wallet first.', '#f0883e');
    return;
  }

  pill.textContent = '⏳ Loading...';
  pill.className = 'balance-pill loading';

  try {
    if (typeof ethers === 'undefined') {
      throw new Error('Ethereum library not loaded. Please refresh.');
    }

    const providerList = providers[coin] || providers['ethereum'];
    let lastError = null;
    let balance = null;
    let formattedBalance = null;

    for (let i = 0; i < providerList.length; i++) {
      try {
        const provider = new ethers.providers.JsonRpcProvider(providerList[i]);
        await provider.getNetwork();

        if (coin === 'usdt') {
          const abi = [
            'function balanceOf(address owner) view returns (uint256)',
            'function decimals() view returns (uint8)'
          ];
          const contract = new ethers.Contract(USDT_ADDRESS, abi, provider);
          balance = await contract.balanceOf(address);
          const decimals = await contract.decimals();
          formattedBalance = ethers.utils.formatUnits(balance, decimals);
        } else {
          balance = await provider.getBalance(address);
          formattedBalance = ethers.utils.formatEther(balance);
        }
        break;
      } catch (error) {
        lastError = error;
        console.warn('RPC failed, trying next...', providerList[i], error.message);
        continue;
      }
    }

    if (balance === null || formattedBalance === null) {
      throw new Error(lastError || 'All RPCs failed');
    }

    const numBalance = parseFloat(formattedBalance);
    let displayText;

    if (numBalance === 0) {
      displayText = '0.00000000 ' + symbol;
    } else if (numBalance < 0.00000001 && numBalance > 0) {
      displayText = numBalance.toExponential(6) + ' ' + symbol;
    } else {
      displayText = numBalance.toFixed(8) + ' ' + symbol;
    }

    pill.textContent = displayText;
    pill.className = 'balance-pill';
    setStatus('✅ Balance: ' + displayText, '#3fb950');
    return formattedBalance;

  } catch (error) {
    console.error('Balance fetch error:', error);
    pill.textContent = '⚠️ ' + symbol + ' unavailable';
    pill.className = 'balance-pill error';
    setStatus('❌ Could not fetch balance: ' + error.message, '#f85149');
    return null;
  }
}

// =============================================
//  دوال النسخ (Copy)
// =============================================

function copyText(elementId) {
  const el = document.getElementById(elementId);
  let text = el.getAttribute('data-value');

  if (!text) {
    const link = el.querySelector('a');
    if (link) {
      text = link.textContent.trim();
    } else {
      const clone = el.cloneNode(true);
      const buttons = clone.querySelectorAll('button');
      buttons.forEach(btn => btn.remove());
      text = clone.textContent.trim();
    }
  }

  if (!text || text === '—' || text === '') {
    setStatus('⚠️ Nothing to copy', '#f0883e');
    return;
  }

  navigator.clipboard.writeText(text)
    .then(() => {
      const btn = el.querySelector('.copy-btn');
      if (btn) {
        btn.textContent = '✅';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = '📋 Copy';
          btn.classList.remove('copied');
        }, 1800);
      }
      setStatus('✅ Copied!', '#3fb950');
    })
    .catch(() => {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setStatus('✅ Copied!', '#3fb950');
    });
}

// نسخ من قائمة التاريخ
function copyHistoryText(text, btn, isPrivate) {
  if (!text) return;

  navigator.clipboard.writeText(text)
    .then(() => {
      btn.textContent = '✅';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = isPrivate ? '🔑 Copy Key' : '📋 Copy';
        btn.classList.remove('copied');
      }, 1500);
      setStatus('✅ Copied!', '#3fb950');
    })
    .catch(() => {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);

      btn.textContent = '✅';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = isPrivate ? '🔑 Copy Key' : '📋 Copy';
        btn.classList.remove('copied');
      }, 1500);
      setStatus('✅ Copied!', '#3fb950');
    });
}

// =============================================
//  دوال إنشاء واستيراد المحفظة (EVM)
// =============================================

function generateEVM(passphrase, coin) {
  try {
    if (typeof ethers === 'undefined') {
      throw new Error('Ethereum library not loaded. Please refresh.');
    }

    const hash = sha256(passphrase);
    const privateKey = '0x' + hash;
    const wallet = new ethers.Wallet(privateKey);

    let networkName = 'Ethereum Mainnet';
    if (coin === 'bnb') networkName = 'BNB Smart Chain';
    else if (coin === 'usdt') networkName = 'Ethereum (ERC-20)';

    return {
      address: wallet.address,
      privateKey: privateKey,
      network: networkName
    };
  } catch (error) {
    console.error('EVM error:', error);
    throw new Error('Failed to generate: ' + error.message);
  }
}

function importEVM(privateKey, coin) {
  try {
    if (typeof ethers === 'undefined') {
      throw new Error('Ethereum library not loaded. Please refresh.');
    }

    let key = privateKey;
    if (!key.startsWith('0x')) key = '0x' + key;
    const wallet = new ethers.Wallet(key);

    let networkName = 'Ethereum Mainnet';
    if (coin === 'bnb') networkName = 'BNB Smart Chain';
    else if (coin === 'usdt') networkName = 'Ethereum (ERC-20)';

    return {
      address: wallet.address,
      privateKey: key,
      network: networkName
    };
  } catch (error) {
    console.error('EVM import error:', error);
    throw new Error('Failed to import: ' + error.message);
  }
}

// =============================================
//  دوال المفتاح السري (Seed / Mnemonic)
// =============================================

function generateMnemonic() {
  try {
    const wordList = [
      'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
      'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
      'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit',
      'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
      'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert',
      'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always'
    ];

    let mnemonic = '';
    for (let i = 0; i < 12; i++) {
      mnemonic += wordList[Math.floor(Math.random() * wordList.length)] + ' ';
    }
    mnemonic = mnemonic.trim();

    currentMnemonic = mnemonic;
    document.getElementById('mnemonicInput').value = mnemonic;
    setMnemonicStatus('✅ Seed phrase generated successfully', '#3fb950');
    importMnemonic();
  } catch (error) {
    console.error('Mnemonic error:', error);
    setMnemonicStatus('❌ Error: ' + error.message, '#f85149');
  }
}

function importMnemonic() {
  const coin = document.getElementById('mnemonicCoinSelect').value;
  const mnemonic = document.getElementById('mnemonicInput').value.trim();

  if (!mnemonic) {
    setMnemonicStatus('⚠️ Please enter a seed phrase', '#f0883e');
    return;
  }

  setMnemonicStatus('⏳ Importing seed phrase...', '#f0883e', true);

  setTimeout(() => {
    try {
      if (typeof ethers === 'undefined') {
        throw new Error('Ethereum library not loaded. Please refresh.');
      }

      const seed = sha256(mnemonic);
      const privateKey = sha256(seed).slice(0, 64);
      const wallet = new ethers.Wallet('0x' + privateKey);

      let networkName = 'Ethereum Mainnet';
      if (coin === 'bnb') networkName = 'BNB Smart Chain';
      else if (coin === 'usdt') networkName = 'Ethereum (ERC-20)';

      const result = {
        address: wallet.address,
        privateKey: '0x' + privateKey,
        network: networkName
      };

      displayResult(coin, result, mnemonic);
      document.getElementById('mnemonicRow').style.display = 'flex';
      document.getElementById('networkRow').style.display = 'flex';
      document.getElementById('networkDisplay').innerHTML = '<span style="color:#8a9db8;">' + result.network + '</span>';

      // إضافة إلى السجل
      addHistory(coin, result.address, result.privateKey, mnemonic);

      setMnemonicStatus('✅ Seed phrase imported successfully', '#3fb950');
      setTimeout(fetchBalance, 800);
    } catch (error) {
      console.error(error);
      setMnemonicStatus('❌ Error: ' + error.message, '#f85149');
    }
  }, 100);
}

// =============================================
//  دوال التبديل بين علامات التبويب
// =============================================

function switchTab(tab) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  document.querySelector('.tab-btn[data-tab="' + tab + '"]').classList.add('active');
}

// =============================================
//  دوال إنشاء المحفظة (زر Generate)
// =============================================

function generateAddress() {
  const coin = document.getElementById('coinSelect').value;
  const passphrase = document.getElementById('passphrase').value.trim();

  if (!passphrase) {
    setStatus('⚠️ Please enter a passphrase', '#f0883e');
    return;
  }

  setStatus('⏳ Generating...', '#f0883e', true);

  setTimeout(() => {
    try {
      const result = generateEVM(passphrase, coin);
      displayResult(coin, result);
      document.getElementById('mnemonicRow').style.display = 'none';
      document.getElementById('networkRow').style.display = 'flex';
      document.getElementById('networkDisplay').innerHTML = '<span style="color:#8a9db8;">' + result.network + '</span>';

      // إضافة إلى السجل
      addHistory(coin, result.address, result.privateKey);

      setStatus('✅ Generated ' + coinNames[coin] + ' successfully', '#3fb950');
      setTimeout(fetchBalance, 800);
    } catch (error) {
      console.error(error);
      setStatus('❌ Error: ' + error.message, '#f85149');
    }
  }, 100);
}

// =============================================
//  دوال استيراد المحفظة (زر Import)
// =============================================

function importWallet() {
  const coin = document.getElementById('importCoinSelect').value;
  const privateKey = document.getElementById('privateKeyInput').value.trim();

  if (!privateKey) {
    setImportStatus('⚠️ Please enter a private key', '#f0883e');
    return;
  }

  setImportStatus('⏳ Importing...', '#f0883e', true);

  setTimeout(() => {
    try {
      const result = importEVM(privateKey, coin);
      displayResult(coin, result);
      document.getElementById('mnemonicRow').style.display = 'none';
      document.getElementById('networkRow').style.display = 'flex';
      document.getElementById('networkDisplay').innerHTML = '<span style="color:#8a9db8;">' + result.network + '</span>';

      // إضافة إلى السجل
      addHistory(coin, result.address, result.privateKey);

      setImportStatus('✅ Imported ' + coinNames[coin] + ' successfully', '#3fb950');
      setTimeout(fetchBalance, 800);
    } catch (error) {
      console.error(error);
      setImportStatus('❌ Error: ' + error.message, '#f85149');
    }
  }, 100);
}

// =============================================
//  عرض النتائج في الواجهة
// =============================================

function displayResult(coin, result, mnemonic) {
  currentAddress = result.address;
  currentCoin = coin;
  currentPrivateKey = result.privateKey;

  const explorer = coinExplorers[coin] || '#';

  // عرض العنوان
  const addressEl = document.getElementById('addressDisplay');
  addressEl.setAttribute('data-value', result.address);
  addressEl.innerHTML = `
    <a href="${explorer}${result.address}" target="_blank">${result.address}</a>
    <button class="copy-btn" onclick="copyText('addressDisplay')" style="margin-left:auto;">📋 Copy</button>
  `;

  // عرض المفتاح الخاص
  const privateEl = document.getElementById('privateDisplay');
  privateEl.setAttribute('data-value', result.privateKey);
  privateEl.innerHTML = `
    <span class="full-key">${result.privateKey}</span>
    <button class="copy-btn" onclick="copyText('privateDisplay')" style="margin-left:auto;">📋 Copy</button>
  `;

  // إعادة تعيين الرصيد
  document.getElementById('balancePill').textContent = '⏳ Loading...';
  document.getElementById('balancePill').className = 'balance-pill loading';

  // عرض المفتاح السري (إن وجد)
  if (mnemonic) {
    const mnemonicEl = document.getElementById('mnemonicDisplay');
    mnemonicEl.setAttribute('data-value', mnemonic);
    mnemonicEl.innerHTML = `
      <span class="full-key">${mnemonic}</span>
      <button class="copy-btn" onclick="copyText('mnemonicDisplay')" style="margin-left:auto;">📋 Copy</button>
    `;
  }
}

// =============================================
//  إدارة سجل العناوين (History) - بدون syncData
// =============================================

function addHistory(coin, address, privateKey, mnemonic) {
  if (!Array.isArray(walletHistory)) walletHistory = [];

  // منع التكرار
  const isDuplicate = walletHistory.some(item =>
    item.address.toLowerCase() === address.toLowerCase()
  );

  if (isDuplicate) {
    setStatus('⚠️ This address already exists in the list', '#f0883e');
    return;
  }

  walletHistory.unshift({
    coin: coin,
    address: address,
    privateKey: privateKey,
    mnemonic: mnemonic || '',
    time: new Date().toLocaleTimeString('en-US')
  });

  renderHistory();

  try {
    localStorage.setItem('walletHistory', JSON.stringify(walletHistory));
  } catch (e) {}
}

function renderHistory() {
  const list = document.getElementById('historyList');
  const count = document.getElementById('historyCount');

  if (!Array.isArray(walletHistory)) walletHistory = [];

  if (walletHistory.length === 0) {
    list.innerHTML = '<div style="padding:16px;text-align:center;color:#5a6a7a;font-size:13px;">No addresses yet</div>';
    count.textContent = '0';
    return;
  }

  let html = '';
  for (let i = 0; i < walletHistory.length; i++) {
    const item = walletHistory[i];
    const shortKey = item.privateKey.substring(0, 10) + '...' + item.privateKey.slice(-8);
    const emoji = coinEmojis[item.coin] || '🔷';

    html += `
      <div class="history-item">
        <div class="history-top">
          <span class="coin-tag">${emoji}</span>
          <span class="addr">${item.address}</span>
          <span class="time">${item.time || ''}</span>
        </div>
        <div class="history-bottom">
          <span class="private-key-preview">🔑 ${shortKey}</span>
          <div class="copy-group">
            <button class="history-copy-btn" onclick="copyHistoryText('${item.address.replace(/'/g, "\\'")}', this, false)">📋 Copy</button>
            <button class="history-copy-btn private-copy" onclick="copyHistoryText('${item.privateKey.replace(/'/g, "\\'")}', this, true)">🔑 Copy Key</button>
          </div>
        </div>
      </div>
    `;
  }

  list.innerHTML = html;
  count.textContent = walletHistory.length;
}

// =============================================
//  دوال تحديث حالة الرسائل (Status)
// =============================================

function setStatus(msg, color, spinner) {
  const el = document.getElementById('statusMsg');
  if (spinner) {
    el.innerHTML = '<span class="spinner"></span> ' + msg;
  } else {
    el.innerHTML = '<span style="color:' + (color || '#8a9db8') + ';">' + msg + '</span>';
  }
}

function setImportStatus(msg, color, spinner) {
  const el = document.getElementById('importStatus');
  if (spinner) {
    el.innerHTML = '<span class="spinner"></span> ' + msg;
  } else {
    el.innerHTML = '<span style="color:' + (color || '#8a9db8') + ';">' + msg + '</span>';
  }
}

function setMnemonicStatus(msg, color, spinner) {
  const el = document.getElementById('mnemonicStatus');
  if (spinner) {
    el.innerHTML = '<span class="spinner"></span> ' + msg;
  } else {
    el.innerHTML = '<span style="color:' + (color || '#8a9db8') + ';">' + msg + '</span>';
  }
}

// =============================================
//  دوال مساعدة (Random Passphrase)
// =============================================

function randomPass() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+';
  let result = '';
  for (let i = 0; i < 28; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  document.getElementById('passphrase').value = result;
  generateAddress();
}

// =============================================
//  تشغيل عند تحميل الصفحة
// =============================================

window.onload = function () {
  walletHistory = [];
  try {
    const saved = localStorage.getItem('walletHistory');
    if (saved) {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed)) {
        walletHistory = parsed;
      }
      renderHistory();
    }
  } catch (e) {}

  setStatus('✅ Ready — Enter your passphrase', '#8a9db8');
};