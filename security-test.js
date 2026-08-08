/* Security Lab engine: static source rules + dynamic exploit probes on the
 * in-browser EVM. Produces a severity-tagged report (sellable audit output).
 * No backend; everything runs client-side.
 */
import { VM } from '@ethereumjs/vm';
import { Address } from '@ethereumjs/util';
import { Common } from '@ethereumjs/common';
import { keccak_256 } from '@noble/hashes/sha3';
import { Buffer } from 'node:buffer';

const OWNER = '0x1111111111111111111111111111111111111111';
const ATTACKER = '0x2222222222222222222222222222222222222222';

function hexWord(v) { return v.toString(16).padStart(64, '0'); }
function padAddr(addr) { return '000000000000000000000000' + addr.slice(2).toLowerCase(); }

function sigOf(frag) {
  return frag.name + '(' + frag.inputs.map(i => i.type).join(',') + ')';
}

function guessArg(t, i) {
  if (t === 'address') return i === 0 ? ATTACKER : '0x0000000000000000000000000000000000000000';
  if (t === 'bool') return true;
  if (t === 'string') return '';
  if (t === 'bytes') return '0x';
  if (/^uint(\d+)?$/.test(t)) return 1n;
  if (/^int(\d+)?$/.test(t)) return 1n;
  return 0n;
}

function encodeCall(frag, values) {
  const sel = keccak_256(new TextEncoder().encode(sigOf(frag))).subarray(0, 4);
  let head = '';
  let tail = '';
  (frag.inputs || []).forEach((inp, i) => {
    const t = inp.type;
    const v = values[i];
    if (t === 'address') head += padAddr(v);
    else if (t === 'bool') head += hexWord(v ? 1n : 0n);
    else if (/^uint(\d+)?$/.test(t)) head += hexWord(BigInt(v));
    else if (/^int(\d+)?$/.test(t)) head += BigInt(v) < 0n ? hexWord((1n << 256n) + BigInt(v)) : hexWord(BigInt(v));
    else if (t === 'string') {
      const bytes = Buffer.from(String(v), 'utf8');
      head += hexWord(BigInt(head.length / 2));
      tail += hexWord(BigInt(bytes.length)) + bytes.toString('hex').padEnd(64, '0');
    } else if (t === 'bytes') {
      const bytes = Buffer.from(String(v).slice(2), 'hex');
      head += hexWord(BigInt(head.length / 2));
      tail += hexWord(BigInt(bytes.length)) + bytes.toString('hex').padEnd(64, '0');
    } else {
      throw new Error('Unsupported type in security probe: ' + t);
    }
  });
  return Buffer.from(Buffer.from(sel).toString('hex') + head + tail, 'hex');
}

function findLine(source, index) {
  if (index == null) return 0;
  return source.slice(0, index).split('\n').length;
}

// ---------- Static source rules ----------
const STATIC_RULES = [
  {
    id: 'tx-origin', sev: 'High', title: 'استفاده از tx.origin',
    re: /\btx\.origin\b/,
    desc: 'tx.origin به جای msg.sender برای اعتبارسنجی استفاده شده — قابل فیشینگ از طریق قرارداد واسط.',
    fix: 'به جای tx.origin از msg.sender استفاده کنید.'
  },
  {
    id: 'selfdestruct', sev: 'High', title: 'selfdestruct',
    re: /\bselfdestruct\b|\bsuicide\b/,
    desc: 'selfdestruct اجازه حذف قرارداد و انتقال اجباری وجوه را می‌دهد.',
    fix: 'اگر ضروری نیست حذف شود؛ دسترسی آن فقط به owner با قفل زمانی محدود شود.'
  },
  {
    id: 'delegatecall', sev: 'High', title: 'delegatecall',
    re: /\bdelegatecall\b/,
    desc: 'delegatecall در حافظه فراخوانی‌کننده اجرا می‌شود؛ اگر آدرس هدف کنترل نشود، کل قرارداد در خطر است.',
    fix: 'از delegatecall اجتناب کنید یا آدرس هدف را صرفاً با allowlist دقیق ببندید.'
  },
  {
    id: 'raw-call-value', sev: 'Medium', title: 'فراخوانی سطح پایین با value',
    re: /\.(call|send|transfer)\s*\{value\s*:/,
    desc: 'ارسال اتر با call سطح پایین؛ بازگشت آن چک نشده و در معرض reentrancy است.',
    fix: 'از الگوی Checks-Effects-Interactions و reentrancy guard استفاده کنید.'
  },
  {
    id: 'reentrancy', sev: 'Medium', title: 'ریسک Reentrancy',
    re: /\.(call|send|transfer)\s*\{?\s*value|\.call\s*\(/,
    desc: 'در جایی فراخوانی خارجی انجام شده؛ اگر با guard نباشد، امکان ورود مجدد وجود دارد.',
    fix: 'guard ضد ورود مجدد (nonReentrant) و ترتیب CEI را رعایت کنید.'
  },
  {
    id: 'assembly', sev: 'Low', title: 'کد assembly',
    re: /\bassembly\b/,
    desc: 'کد اسمبلی مدیریت دستی حافظه/بایت‌کد — خطاپذیر و غیراستاندارد.',
    fix: 'تا حد ممکن به Solidity خالص محدود شود.'
  },
  {
    id: 'unchecked', sev: 'Low', title: 'بلاک unchecked',
    re: /\bunchecked\b/,
    desc: 'محاسبات داخل unchecked overflow را چک نمی‌کند.',
    fix: 'فقط جایی استفاده شود که سرریز ریاضی اثبات‌شده غیرممکن است.'
  },
  {
    id: 'timestamp', sev: 'Low', title: 'مقایسه block.timestamp',
    re: /\bblock\.timestamp\b/,
    desc: 'اعتماد به timestamp برای قفل/بخت‌آزمایی — معدن‌چی می‌تواند آن را کمی تغییر دهد.',
    fix: 'مقادیر بازه‌ای (چند بلوک) به جای نقطه‌ای در نظر بگیرید.'
  },
  {
    id: 'blockhash', sev: 'Low', title: 'استفاده از blockhash',
    re: /\bblockhash\b/,
    desc: 'blockhash فقط برای ~۲۵۶ بلوک اخیر معتبر است و قابل حدس/دستکاری در محدوده کوچک است.',
    fix: 'برای تصادفی بودن از منبع قابل اعتماد یا commit-reveal استفاده کنید.'
  },
  {
    id: 'sol-0-7', sev: 'High', title: 'نسخه قدیمی بدون چک سرریز',
    re: /pragma\s+solidity\s+(\^|>=|)\s*0\.[0-7]\./,
    desc: 'نسخه پیش از 0.8 چک داخلی overflow/underflow ندارد — سرریزهای ریاضی بسیار محتمل‌اند.',
    fix: 'به 0.8.x ارتقا دهید.'
  },
  {
    id: 'no-onlyowner-mint', sev: 'Medium', title: 'mint بدون گارد مالک قابل تشخیص',
    re: /\bfunction\s+mint\b/,
    desc: 'تابع mint پیدا شد؛ مطمئن شوید فقط owner می‌تواند صدا بزند (تست داینامیک همین را می‌سنجد).',
    fix: 'modifier فقط‌مالک و چک صفر برای آدرس بگیرنده بگذارید.'
  },
  {
    id: 'no-onlyowner-burn-any', sev: 'Info', title: 'burn عمومی',
    re: /\bfunction\s+burn\b/,
    desc: 'burn عمومی یعنی هر کس توکن خودش را بسوزاند — معمولاً بی‌خطر، ولی اگر burn دیگران را بسوزاند خطرناک است.',
    fix: 'مطمئن شوید burn فقط بالانس فراخوان‌کننده را کم می‌کند.'
  },
  {
    id: 'zero-address', sev: 'Medium', title: 'عدم چک آدرس صفر در انتقال مالکیت',
    re: /transferOwnership\s*\(/,
    desc: 'انتقال مالکیت بدون چک آدرس صفر می‌تواند مالکیت را برای همیشه از بین ببرد (تست داینامیک سنجیده می‌شود).',
    fix: 'require(newOwner != address(0)).'
  },
  {
    id: 'hardcoded-addr', sev: 'Info', title: 'آدرس سخت‌کد شده',
    re: /0x[a-fA-F0-9]{40}/,
    desc: 'آدرس ثابت در کد دیده می‌شود — مطمئن شوید قابل اعتماد و مستند است.',
    fix: 'آدرس‌های حساس را در constructor قابل تنظیم کنید.'
  },
  {
    id: 'centralization', sev: 'Info', title: 'ریسک متمرکزسازی (مالک می‌تواند rug)',
    re: /onlyOwner|_owner|owner\b/i,
    desc: 'قرارداد مالک دارد؛ بررسی کنید مالک نمی‌تواند بالانس دیگران را مصادره یا توکن را غیرقابل فروش کند.',
    fix: 'قفل زمانی، چند امضایی یا توابع بدون rug در نظر بگیرید.'
  },
  {
    id: 'http-import', sev: 'High', title: 'import از آدرس http',
    re: /import\s+["']https?:\/\//,
    desc: 'import از آدرس نامطمئن = supply-chain risk.',
    fix: 'کدها را کپی کنید یا فقط از منابع معروف (OpenZeppelin) با پین نسخه استفاده کنید.'
  },
  {
    id: 'pragma-exact', sev: 'Info', title: 'نسخه pragma ثابت',
    re: /pragma\s+solidity\s*=\s*[^;]+;/,
    desc: 'پین کردن نسخه دقیق، ارتقای امنیتی را سخت می‌کند.',
    fix: 'از ^ استفاده کنید.'
  },
  {
    id: 'experimental', sev: 'Info', title: 'pragma experimental',
    re: /pragma\s+experimental/,
    desc: 'ویژگی‌های آزمایشی ممکن است تغییر/خطا داشته باشند.',
    fix: 'از آن اجتناب کنید مگر کاملاً لازم باشد.'
  }
];

export function staticScan(source) {
  const findings = [];
  STATIC_RULES.forEach(rule => {
    const m = source.match(rule.re);
    if (m) {
      findings.push({
        id: rule.id,
        sev: rule.sev,
        title: rule.title,
        detail: rule.desc,
        fix: rule.fix,
        line: findLine(source, m.index),
        kind: 'static'
      });
    }
  });
  // reentrancy guard cross-check
  const hasGuard = /nonReentrant|ReentrancyGuard|locked\s*=/i.test(source);
  const hasExternalCall = /\.(call|send|transfer)\b|\.call\s*\{?value/i.test(source);
  if (hasExternalCall && !hasGuard) {
    findings.push({
      id: 'reentrancy-guard', sev: 'Medium', title: 'نداشتن guard ضد ورود مجدد',
      detail: 'فراخوانی خارجی وجود دارد ولی هیچ nonReentrant/ReentrancyGuard دیده نمی‌شود.',
      fix: 'به توابع دارای فراخوانی خارجی، modifier ضد ورود مجدد اضافه کنید.',
      line: 0, kind: 'static'
    });
  }
  return findings;
}

// ---------- Dynamic probes (deploy + attempt attacks in the browser EVM) ----------
const PRIVILEGED = /^(set|update|add|remove|withdraw|rescue|claim|mint|pause|setPaused|transferOwnership|renounceOwnership|forceUnlock|setBlacklisted|setWhitelisted|setExcluded|setWhaleExempt|setMaxTx|setTax|setBuySellTax|setMarketingWallet|setPair|setAntiWhale|emergency|kill|destroy|admin|governance|config)/i;

function hasFn(abi, name) { return abi.some(f => f.type === 'function' && f.name === name); }
function fragOf(abi, name) { return abi.find(f => f.type === 'function' && f.name === name); }
function isView(frag) { return frag.stateMutability === 'view' || frag.stateMutability === 'pure'; }

async function deployContract(vm, bytecode) {
  const create = await vm.evm.runCall({
    caller: Address.fromString(OWNER), to: undefined,
    data: Buffer.from(bytecode.slice(2), 'hex'),
    gasLimit: 0xFFFFFFFFn, gasPrice: 1n, value: 0n
  });
  const addr = create.createdAddress || (create.execResult && create.execResult.createdAddress);
  return addr;
}

async function call(vm, from, to, data) {
  const r = await vm.evm.runCall({
    caller: Address.fromString(from), to,
    data, gasLimit: 0xFFFFFFFFn, gasPrice: 1n, value: 0n
  });
  const err = (r.execResult && r.execResult.exceptionError) || r.exceptionError;
  return { reverted: !!err, error: err ? String(err.error) : null };
}

export async function runSecurityTests(abi, bytecode, source) {
  const started = Date.now();
  const probes = [];
  const record = (name, attackSucceeded, sev, detail) => {
    probes.push({
      name, kind: 'dynamic',
      secure: !attackSucceeded,
      sev,
      detail: attackSucceeded
        ? '⚠ حمله موفق شد: ' + detail
        : 'حملهمقابل دفع شد: ' + detail
    });
  };

  const common = Common.custom({ chainId: 1 }, { hardfork: 'cancun' });
  const vm = await VM.create({ common });
  const addr = await deployContract(vm, bytecode);
  if (!addr) {
    return { probes: [{ name: 'deploy', kind: 'dynamic', secure: false, sev: 'Critical', detail: 'قرارداد deploy نشد.' }], durationMs: Date.now() - started };
  }

  // 1. Owner-only scan: try each privileged function from the attacker.
  const privilegedFns = abi.filter(f => f.type === 'function' && !isView(f) && PRIVILEGED.test(f.name));
  const exploited = [];
  for (const f of privilegedFns) {
    let values;
    try {
      values = (f.inputs || []).map((inp, i) => guessArg(inp.type, i));
    } catch (e) { continue; }
    let r;
    try {
      r = await call(vm, ATTACKER, addr, encodeCall(f, values));
    } catch (e) { continue; }
    if (!r.reverted) {
      exploited.push(f.name);
    }
  }
  if (exploited.length) {
    record('کنترل دسترسی توابع ویژه', true, 'High', 'توابع ' + exploited.join(', ') + ' برای هر کس قابل فراخوانی هستند (بدون revert از سمت غیرمالک).');
  } else {
    record('کنترل دسترسی توابع ویژه', false, 'Info', 'هیچ تابع ویژه‌ای از طرف غیرمالک قابل فراخوانی نبود (تا حدی که در EVM شبیه‌سازی شد).');
  }

  // 2. mint from attacker.
  if (hasFn(abi, 'mint')) {
    const r = await call(vm, ATTACKER, addr, encodeCall(fragOf(abi, 'mint'), [ATTACKER, 1000000n]));
    record('سوءاستفاده از mint توسط هر کس', !r.reverted, 'Critical', !r.reverted ? 'حمله‌کننده بدون اجازه mint کرد.' : 'فقط مالک می‌تواند mint کند.');
  } else {
    record('سوءاستفاده از mint', false, 'Info', 'تابع mint وجود ندارد.');
  }

  // 3. pause / unpause from attacker.
  for (const fn of ['setPaused', 'pause', 'unpause']) {
    if (hasFn(abi, fn)) {
      const r = await call(vm, ATTACKER, addr, encodeCall(fragOf(abi, fn), []));
      record('توقف/لغو توقف توسط هر کس (' + fn + ')', !r.reverted, 'High', !r.reverted ? 'غیرمالک توانست وضعیت توقف را تغییر دهد.' : 'فقط مالک.');
    }
  }

  // 4. attacker blacklists the owner.
  if (hasFn(abi, 'setBlacklisted')) {
    const f = fragOf(abi, 'setBlacklisted');
    const r = await call(vm, ATTACKER, addr, encodeCall(f, [OWNER, true]));
    record('بلاک‌لیست کردن مالک توسط حمله‌کننده', !r.reverted, 'High', !r.reverted ? 'هر کس می‌تواند مالک را بلاک کند.' : 'فقط مالک.');
  }

  // 5. attacker whitelists himself.
  if (hasFn(abi, 'setWhitelisted')) {
    const f = fragOf(abi, 'setWhitelisted');
    const r = await call(vm, ATTACKER, addr, encodeCall(f, [ATTACKER, true]));
    record('وایت‌لیست شدن خود توسط حمله‌کننده', !r.reverted, 'High', !r.reverted ? 'حمله‌کننده خودش را وایت‌لیست کرد (دور زدن وایت‌لیست).' : 'فقط مالک.');
  }

  // 6. attacker excludes himself from tax.
  for (const fn of ['setExcluded', 'setTaxExcluded']) {
    if (hasFn(abi, fn)) {
      const f = fragOf(abi, fn);
      const r = await call(vm, ATTACKER, addr, encodeCall(f, [ATTACKER, true]));
      record('معافیت مالیاتی خود توسط حمله‌کننده (' + fn + ')', !r.reverted, 'High', !r.reverted ? 'حمله‌کننده خودش را از مالیات معاف کرد.' : 'فقط مالک.');
    }
  }

  // 7. forceUnlock from attacker.
  if (hasFn(abi, 'forceUnlock')) {
    const f = fragOf(abi, 'forceUnlock');
    const r = await call(vm, ATTACKER, addr, encodeCall(f, [ATTACKER]));
    record('باز کردن قفل خود توسط حمله‌کننده (forceUnlock)', !r.reverted, 'High', !r.reverted ? 'حمله‌کننده قفل خودش را باز کرد.' : 'فقط مالک.');
  }

  // 8. transferOwnership from attacker.
  if (hasFn(abi, 'transferOwnership')) {
    const f = fragOf(abi, 'transferOwnership');
    const r = await call(vm, ATTACKER, addr, encodeCall(f, [ATTACKER]));
    record('ربودن مالکیت توسط حمله‌کننده', !r.reverted, 'Critical', !r.reverted ? 'هر کس می‌تواند مالک شود!' : 'فقط مالک.');
  }

  // 9. transferOwnership(0x0) from owner — zero-address.
  if (hasFn(abi, 'transferOwnership')) {
    const f = fragOf(abi, 'transferOwnership');
    const r = await call(vm, OWNER, addr, encodeCall(f, ['0x0000000000000000000000000000000000000000']));
    record('انتقال مالکیت به آدرس صفر توسط مالک', !r.reverted, 'Medium', !r.reverted ? 'مالک می‌تواند مالکیت را به آدرس صفر بدهد (قرارداد بی‌سرپرست می‌شود).' : 'چک آدرس صفر وجود دارد.');
  }

  // 10. withdraw / rescue from attacker.
  const withdrawFns = abi.filter(f => f.type === 'function' && !isView(f) && /^(withdraw|rescue|claimStuck|recover|sweep|emergencyWithdraw|claimFees|flush)/i.test(f.name));
  for (const f of withdrawFns.slice(0, 3)) {
    let values;
    try {
      values = (f.inputs || []).map((inp, i) => guessArg(inp.type, i));
    } catch (e) { continue; }
    const r = await call(vm, ATTACKER, addr, encodeCall(f, values));
    record('برداشت/نجات وجوه توسط هر کس (' + f.name + ')', !r.reverted, 'High', !r.reverted ? 'غیرمالک توانست تابع برداشت را اجرا کند.' : 'فقط مالک.');
  }

  // 11. Lock bypass: owner funds attacker, attacker locks self, then tries transfer.
  if (hasFn(abi, 'lock') && hasFn(abi, 'transfer')) {
    const okT = await call(vm, OWNER, addr, encodeCall(fragOf(abi, 'transfer'), [ATTACKER, 10n]));
    if (!okT.reverted) {
      const lockF = fragOf(abi, 'lock');
      const until = BigInt(Math.floor(Date.now() / 1000)) + 2000000n;
      await call(vm, ATTACKER, addr, encodeCall(lockF, [ATTACKER, until]));
      const t2 = await call(vm, ATTACKER, addr, encodeCall(fragOf(abi, 'transfer'), [OWNER, 1n]));
      record('دور زدن قفل سرمایه‌گذار (Lock)', !t2.reverted, 'High', !t2.reverted ? 'توکن‌های قفل‌شده قابل انتقال بودند.' : 'قفل، انتقال را مسدود کرد.');
    } else {
      record('دور زدن قفل سرمایه‌گذار', false, 'Info', 'نتوانستیم موجودی اولیه به حمله‌کننده بدهیم (تست رد شد).');
    }
  }

  // 12. MaxTx / anti-whale limits from attacker (setting limits).
  for (const fn of ['setMaxTx', 'setAntiWhale']) {
    if (hasFn(abi, fn)) {
      const f = fragOf(abi, fn);
      let values;
      try {
        values = (f.inputs || []).map((inp, i) => guessArg(inp.type, i));
      } catch (e) { continue; }
      const r = await call(vm, ATTACKER, addr, encodeCall(f, values));
      record('تغییر محدودیت‌های تراکنش/نهنگ توسط هر کس (' + fn + ')', !r.reverted, 'High', !r.reverted ? 'غیرمالک توانست محدودیت‌ها را تغییر دهد.' : 'فقط مالک.');
    }
  }

  // 13. whitelist enforcement: attacker toggles whitelist enabled.
  if (hasFn(abi, 'setWhitelistEnabled')) {
    const f = fragOf(abi, 'setWhitelistEnabled');
    const r = await call(vm, ATTACKER, addr, encodeCall(f, [true]));
    record('فعال/غیرفعال کردن وایت‌لیست توسط هر کس', !r.reverted, 'High', !r.reverted ? 'غیرمالک وایت‌لیست را تغییر داد.' : 'فقط مالک.');
  }

  return { probes, durationMs: Date.now() - started };
}

// ---------- Report ----------
export function buildReport(source, abi, bytecode, staticFindings, dynamic) {
  const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const all = staticFindings.map(f => ({ ...f })).concat(dynamic.probes.map(p => ({
    id: 'dyn-' + p.name, sev: p.secure ? 'Info' : p.sev,
    title: p.name, detail: p.detail, fix: '', line: 0, kind: 'dynamic'
  })));

  // Downgrade heuristic static findings whose risk was dynamically disproved
  // by a successful EVM simulation (avoids false positives on guarded code).
  const secureProbes = (dynamic.probes || []).filter(p => p.secure).map(p => p.name);
  const remap = [
    { id: 'no-onlyowner-mint', kw: 'mint' },
    { id: 'zero-address', kw: 'آدرس صفر' }
  ];
  all.forEach(f => {
    if (f.kind !== 'static') return;
    const rule = remap.find(r => r.id === f.id && secureProbes.some(n => n.includes(r.kw)));
    if (rule) {
      f.sev = 'Info';
      f.detail = f.detail + ' — تأیید داینامیک در EVM مرورگر این مورد را ایمن نشان داد.';
      f.dynConfirmed = true;
    }
  });
  const bySev = {};
  all.forEach(f => { bySev[f.sev] = (bySev[f.sev] || 0) + 1; });
  const counts = {
    Critical: bySev.Critical || 0, High: bySev.High || 0, Medium: bySev.Medium || 0,
    Low: bySev.Low || 0, Info: bySev.Info || 0
  };
  all.sort((a, b) => (sevOrder[a.sev] - sevOrder[b.sev]));
  return { findings: all, counts, durationMs: dynamic.durationMs, contractCount: (abi || []).length };
}

export function reportToMarkdown(report, fileName) {
  const lines = [];
  lines.push('# گزارش امنیتی قرارداد — ' + (fileName || 'نامشخص'));
  lines.push('');
  lines.push('### خلاصه');
  lines.push('');
  lines.push('| شدت | تعداد |');
  lines.push('|-----|-------|');
  lines.push('| Critical | ' + report.counts.Critical + ' |');
  lines.push('| High | ' + report.counts.High + ' |');
  lines.push('| Medium | ' + report.counts.Medium + ' |');
  lines.push('| Low | ' + report.counts.Low + ' |');
  lines.push('| Info | ' + report.counts.Info + ' |');
  lines.push('');
  lines.push('مدت تحلیل: ' + report.durationMs + 'ms');
  lines.push('');
  report.findings.forEach((f, i) => {
    lines.push('## ' + (i + 1) + '. [' + f.sev + '] ' + f.title);
    lines.push('');
    lines.push('**نوع:** ' + (f.kind === 'dynamic' ? 'پویا (EVM مرورگر)' : 'استاتیک (سورس)'));
    lines.push('');
    lines.push(f.detail);
    if (f.fix) {
      lines.push('');
      lines.push('**راه‌حل:** ' + f.fix);
    }
    lines.push('');
  });
  return lines.join('\n');
}
