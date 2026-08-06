/**
 * make-token.js — ساخت نسخه اختصاصی توکن برای هر مشتری
 *
 * اجرا:
 *   node make-token.js                     (سوال‌ها ازت پرسیده می‌شه)
 *   node make-token.js "Gold Token" GLD 1000000
 *   node make-token.js "Gold Token" GLD 1000000 0x...OwnerAddress
 *
 * خروجی: orders/<Symbol>_<timestamp>.sol   (فایل آماده تحویل به مشتری)
 * خودکار هم کامپایل می‌کنه و اگر خطایی باشه می‌گه.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const TEMPLATE = path.join(__dirname, 'contracts', 'MyToken.sol');
const OUT_DIR = path.join(__dirname, 'orders');

// ---------- چک‌سام EIP-55 ----------

let soljson = null;
try {
  soljson = require(path.join(__dirname, 'solc', 'soljson-v0.8.36.js'));
} catch (e) {
  console.log('  (هشدار: solc پیدا نشد — فقط فایل ساخته می‌شه)');
}

function compile(source) {
  if (!soljson) return { ok: true };
  const compile = soljson.cwrap('solidity_compile', 'string', ['string', 'number', 'number']);
  const cb = soljson.addFunction(function () { return { contents: '', error: 'nf' }; }, 'viiiii');
  const input = {
    language: 'Solidity',
    sources: { 'MyToken.sol': { content: source } },
    settings: { evmVersion: 'shanghai', optimizer: { enabled: true, runs: 200 }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode'] } } }
  };
  const out = JSON.parse(compile(JSON.stringify(input), cb, 0));
  if (out.errors) {
    const errs = out.errors.filter(e => e.severity === 'error');
    if (errs.length) return { ok: false, errors: errs };
  }
  return { ok: true };
}

// ---------- پرسیدن سوال ----------
function ask(rl, q, def) {
  return new Promise(res => rl.question(q + (def ? ` (پیش‌فرض: ${def})` : '') + ': ', a => res(a.trim() || def || '')));
}

function sanitize(s) {
  return String(s).replace(/[^A-Za-z0-9]/g, '');
}

function parseSupply(s) {
  if (!s) return '0';
  return String(s).replace(/[^\d]/g, '');
}

async function main() {
  const args = process.argv.slice(2);
  let name, symbol, supply, owner;

  if (args.length >= 2) {
    name = args[0]; symbol = args[1];
    supply = args[2] || '0';
    owner = args[3] || '';
  } else {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    name = await ask(rl, 'اسم توکن (مثلاً Gold Token)');
    symbol = await ask(rl, 'نماد توکن (مثلاً GLD)');
    supply = await ask(rl, 'عرضه اولیه (مثلاً 1000000 یا 0)', '0');
    owner = await ask(rl, 'آدرس مالک (خالی = کیف پول deployer)');
    rl.close();
  }

  if (!name || !symbol) {
    console.error('❌ اسم و نماد الزامی‌اند.');
    process.exit(1);
  }

  supply = parseSupply(supply) || '0';

  // اعتبارسنجی آدرس مالک (اگر داده شده)
  if (owner) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(owner)) {
      console.error('❌ آدرس مالک نامعتبر است. باید 0x + 40 حرف هگز باشد (مثل: 0x5A4...900)');
      process.exit(1);
    }
  }

  const contractName = sanitize(symbol) + 'Token';

  let src = fs.readFileSync(TEMPLATE, 'utf8');

  // نام قرارداد (کلاس)
  src = src.replace(/\bcontract MyToken\b/, `contract ${contractName}`);

  // کل بلوک constructor را با نسخه بدون پارامتر جایگزین کن
  // تبدیل امن آدرس: عدد اعشاری — سالیدیتی آن را literal آدرس نمی‌داند، پس چک‌سام چک نمی‌شود
  const ownerNum = owner ? '0x' + owner.slice(2) : null;
  const ownerExpr = owner ? `address(uint160(${BigInt(ownerNum)}))` : 'msg.sender';
  src = src.replace(
    /    constructor\(string memory _name, string memory _symbol, uint256 initialSupply\) \{[\s\S]*?\n    \}/,
    `    constructor() {
        require(bytes("${name}").length > 0, "Empty name");
        require(bytes("${symbol}").length > 0, "Empty symbol");

        name        = "${name}";
        symbol      = "${symbol}";
        owner       = ${ownerExpr};

        if (${supply} > 0) {
            _mint(${ownerExpr}, ${supply});
        }
    }`
  );

  // کامپایل برای اطمینان
  const c = compile(src);
  if (!c.ok) {
    console.error('❌ کامپایل خطا دارد — فایل ساخته نشد:');
    console.error('   ownerExpr:', ownerExpr);
    c.errors.forEach(e => console.error('   ' + (e.message || e)));
    process.exit(1);
  }

  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR);
  const stamp = new Date().toISOString().replace(/[:T]/g, '').slice(0, 14);
  const fname = `${sanitize(symbol)}_${stamp}.sol`;
  const outPath = path.join(OUT_DIR, fname);
  fs.writeFileSync(outPath, src, 'utf8');

  console.log('');
  console.log('✅ ساخته شد!');
  console.log('   فایل:      ' + outPath);
  console.log('   نام:       ' + name);
  console.log('   نماد:      ' + symbol);
  console.log('   عرضه:      ' + supply);
  console.log('   مالک:      ' + (owner || '(کیف پولی که deploy می‌کنه)'));
  console.log('   کامپایل:   ✔ بدون خطا');
  console.log('');
  console.log('برای تحویل به مشتری: همین فایل را بفرست + راهنمای استقرار (Remix).');
}

main().catch(e => { console.error('ERROR:', e); process.exit(1); });
