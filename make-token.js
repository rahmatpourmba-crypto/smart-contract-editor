/**
 * make-token.js — ساخت نسخه اختصاصی توکن برای هر مشتری
 *
 * دو حالت:
 *   پایه (MyToken)        — mint/burn/lock/ownership
 *   پریمیوم (PremiumToken) — همه موارد پایه + مالیات انتقال + سوزاندن خودکار
 *                            + سقف نگهداری (ضد نهنگ) + معافیت مالیاتی + سوییچ
 *
 * اجرا:
 *   node make-token.js                                  (سوال‌ها ازت پرسیده می‌شه)
 *   node make-token.js "Gold Token" GLD 1000000
 *   node make-token.js "Gold Token" GLD 1000000 0x...OwnerAddress premium 500 30 200
 *                                            │        │       │    │   │   │
 *                                            │        │       │    │   │   └─ سقف نهنگ (درصد با 2 اعشار، 200=2%)
 *                                            │        │       │    │   └─ سهم سوزاندن (درصد از مالیات، 30=30%)
 *                                            │        │       │    └─ مالیات (basis points، 500=5%)
 *                                            │        │       └─ حالت: base یا premium
 *                                            │        └─ آدرس مالک (اختیاری، خالی = deployer)
 *                                            └─ عرضه اولیه (تعداد توکن، خودش ×10^18 می‌شود)
 *
 * خروجی: orders/<Symbol>_<timestamp>.sol   (فایل آماده تحویل به مشتری)
 * خودکار هم کامپایل می‌کنه و اگر خطایی باشه می‌گه.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const OUT_DIR = path.join(__dirname, 'orders');

let soljson = null;
try {
  soljson = require(path.join(__dirname, 'solc', 'soljson-v0.8.36.js'));
} catch (e) {
  console.log('  (هشدار: solc پیدا نشد — فقط فایل ساخته می‌شه)');
}

function compile(source, fileName) {
  if (!soljson) return { ok: true };
  const compile = soljson.cwrap('solidity_compile', 'string', ['string', 'number', 'number']);
  const cb = soljson.addFunction(function () { return { contents: '', error: 'nf' }; }, 'viiiii');
  const input = {
    language: 'Solidity',
    sources: { [fileName]: { content: source } },
    settings: { evmVersion: 'shanghai', optimizer: { enabled: true, runs: 200 }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode'] } } }
  };
  const out = JSON.parse(compile(JSON.stringify(input), cb, 0));
  if (out.errors) {
    const errs = out.errors.filter(e => e.severity === 'error');
    if (errs.length) return { ok: false, errors: errs };
  }
  return { ok: true };
}

function ask(rl, q, def) {
  return new Promise(res => rl.question(q + (def ? ` (پیش‌فرض: ${def})` : '') + ': ', a => res(a.trim() || def || '')));
}

function sanitize(s) {
  return String(s).replace(/[^A-Za-z0-9]/g, '');
}

function parseNum(s) {
  if (!s) return '0';
  return String(s).replace(/[^\d]/g, '');
}

function addrExpr(addr) {
  if (!addr) return 'msg.sender';
  return `address(uint160(${BigInt('0x' + addr.slice(2))}))`;
}

async function main() {
  const args = process.argv.slice(2);
  let name, symbol, supply, owner, mode, taxBp, burnShare, maxWalletPct;

  if (args.length >= 2) {
    name = args[0]; symbol = args[1];
    supply = args[2] || '0';
    // آرگومان ۴ می‌تواند آدرس مالک یا حالت باشد
    const a3 = args[3] || '';
    if (a3.startsWith('0x')) {
      owner = a3;
      mode = (args[4] || 'base').toLowerCase();
      taxBp = args[5] || '';
      burnShare = args[6] || '';
      maxWalletPct = args[7] || '';
    } else {
      owner = '';
      mode = a3.toLowerCase() || 'base';
      taxBp = args[4] || '';
      burnShare = args[5] || '';
      maxWalletPct = args[6] || '';
    }
  } else {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    name = await ask(rl, 'اسم توکن (مثلاً Gold Token)');
    symbol = await ask(rl, 'نماد توکن (مثلاً GLD)');
    supply = await ask(rl, 'عرضه اولیه (مثلاً 1000000 یا 0)', '0');
    owner = await ask(rl, 'آدرس مالک (خالی = کیف پول deployer)');
    mode = (await ask(rl, 'حالت؟ base=پایه / premium=پریمیوم (مالیات+ضد نهنگ)', 'base')).toLowerCase();
    if (mode === 'premium') {
      taxBp = await ask(rl, 'مالیات هر انتقال (درصد، مثلاً 5)', '5');
      burnShare = await ask(rl, 'سهم سوزاندن از مالیات (درصد، مثلاً 30)', '30');
      maxWalletPct = await ask(rl, 'سقف نگهداری هر کیف (درصد، مثلاً 2)', '2');
    }
    rl.close();
  }

  if (!name || !symbol) {
    console.error('❌ اسم و نماد الزامی‌اند.');
    process.exit(1);
  }

  supply = parseNum(supply) || '0';

  if (owner && !/^0x[0-9a-fA-F]{40}$/.test(owner)) {
    console.error('❌ آدرس مالک نامعتبر است. باید 0x + 40 حرف هگز باشد.');
    process.exit(1);
  }

  const isPremium = mode === 'premium' || mode === 'p';
  const templateName = isPremium ? 'PremiumToken.sol' : 'MyToken.sol';
  const srcTemplate = fs.readFileSync(path.join(__dirname, 'contracts', templateName), 'utf8');
  const contractClass = isPremium ? 'PremiumToken' : 'MyToken';
  const contractName = sanitize(symbol) + 'Token';

  // عرضه: تعداد توکن × 10^18 (هر توکن ۱۸ اعشار)
  const supplyRaw = supply === '0' ? '0' : `${supply} * 10 ** 18`;
  const ownerE = addrExpr(owner);
  const ow = owner || 'msg.sender';

  let src = srcTemplate;

  // نام کلاس
  src = src.replace(new RegExp(`\\bcontract ${contractClass}\\b`), `contract ${contractName}`);

  // مقادیر پریمیوم (برای چاپ نتیجه)
  const taxPct = parseNum(taxBp) === '0' ? '0' : (parseNum(taxBp) || '5');
  const burn = parseNum(burnShare) || '30';
  const whale = parseNum(maxWalletPct) || '2';

  if (isPremium) {
    // مالیات (درصد داده‌شده → basis points)
    const taxBpVal = taxPct === '0' ? '0' : String(Number(taxPct) * 100);
    const whaleBp = whale === '0' ? '0' : String(Number(whale) * 100);

    src = src.replace(
      /    constructor\(\) \{[\s\S]*?\n    \}/,
      [
        '    constructor() {',
        `        name            = "${name}";`,
        `        symbol          = "${symbol}";`,
        `        owner           = ${ownerE};`,
        `        marketingWallet = ${ownerE};`,
        `        transferTax     = ${taxBpVal};`,
        `        burnShare       = ${burn};`,
        `        maxWalletPercent= ${whaleBp};`,
        `        taxEnabled      = true;`,
        `        antiWhaleEnabled= true;`,
        `        isTaxExcluded[${ownerE}] = true;`,
        `        isWhaleExempt[${ownerE}] = true;`,
        `        if (${supplyRaw} > 0) {`,
        `            _mint(${ownerE}, ${supplyRaw});`,
        '        }',
        '    }'
      ].join('\n')
    );
  } else {
    src = src.replace(
      /    constructor\(string memory _name, string memory _symbol, uint256 initialSupply\) \{[\s\S]*?\n    \}/,
      [
        '    constructor() {',
        `        require(bytes("${name}").length > 0, "Empty name");`,
        `        require(bytes("${symbol}").length > 0, "Empty symbol");`,
        '',
        `        name   = "${name}";`,
        `        symbol = "${symbol}";`,
        `        owner  = ${ownerE};`,
        '',
        `        if (${supplyRaw} > 0) {`,
        `            _mint(${ownerE}, ${supplyRaw});`,
        '        }',
        '    }'
      ].join('\n')
    );
  }

  const c = compile(src, 'C.sol');
  if (!c.ok) {
    console.error('❌ کامپایل خطا دارد — فایل ساخته نشد:');
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
  console.log('   حالت:      ' + (isPremium ? 'پریمیوم (مالیات+ضد نهنگ)' : 'پایه'));
  console.log('   نام:       ' + name);
  console.log('   نماد:      ' + symbol);
  console.log('   عرضه:      ' + supply + (supply === '0' ? '' : ' توکن (×10^18)'));
  console.log('   مالک:      ' + (owner || '(کیف پولی که deploy می‌کند)'));
  if (isPremium) {
    console.log('   مالیات:    ' + (taxPct === '0' ? 'غیرفعال' : taxPct + '%'));
    console.log('   سوزاندن:   ' + burn + '% از مالیات');
    console.log('   سقف نهنگ:  ' + (whale === '0' ? 'غیرفعال' : whale + '% از عرضه'));
  }
  console.log('   کامپایل:   ✔ بدون خطا');
  console.log('');
  console.log('برای تحویل به مشتری: همین فایل را بفرست + راهنمای استقرار (Remix).');
}

main().catch(e => { console.error('ERROR:', e); process.exit(1); });
