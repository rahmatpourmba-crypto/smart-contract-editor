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

// Strip /* */ and // comments but keep newlines so line numbers stay correct.
function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, m => m.split('').map(ch => (ch === '\n' ? '\n' : ' ')).join(''))
    .replace(/\/\/[^\n]*/g, '');
}

// Find the Solidity contract with the most code (heuristic for multi-file).
function mainSource(source) {
  return source;
}

const STORAGE_ARRAY = /^(holders|users|members|owners|whitelist|blacklist|bids|bidders|list|lists|accounts|approved|claims|tokens|players|participants|stakers|wallets|voters|depositors|array|arrays|ids|items)$/i;

// ---------- Static source rules ----------
const STATIC_RULES = [
  {
    id: 'tx-origin', sev: 'High', title: 'استفاده از tx.origin',
    re: /\btx\.origin\b/,
    desc: 'tx.origin به جای msg.sender برای اعتبارسنجی استفاده شده — قابل فیشینگ از طریق قرارداد واسط.',
    fix: 'به جای tx.origin از msg.sender استفاده کنید.',
    exploit: 'قرارداد واسطی بساز که msg.sender قربانی باشد؛ توابع محافظت‌شده را از آن صدا بزن. اگر با tx.origin==owner پاس شد = باگ.'
  },
  {
    id: 'selfdestruct', sev: 'High', title: 'selfdestruct',
    re: /\bselfdestruct\b|\bsuicide\b/,
    desc: 'selfdestruct اجازه حذف قرارداد و انتقال اجباری وجوه را می‌دهد.',
    fix: 'اگر ضروری نیست حذف شود؛ دسترسی آن فقط به owner با قفل زمانی محدود شود.',
    exploit: 'اگر هر کاربر یا مالک بتواند صدا بزند، کل وجوه/توکن‌ها نابود می‌شود. در PoC از آدرس غیرمالک تست کن.'
  },
  {
    id: 'delegatecall', sev: 'High', title: 'delegatecall',
    re: /\bdelegatecall\b/,
    desc: 'delegatecall در حافظه فراخوانی‌کننده اجرا می‌شود؛ اگر آدرس هدف کنترل نشود، کل قرارداد در خطر است.',
    fix: 'از delegatecall اجتناب کنید یا آدرس هدف را صرفاً با allowlist دقیق ببندید.',
    exploit: 'اگر آدرس هدف از ورودی تابع/state می‌آید، آدرس یک قرارداد مخرب خودت را بده و owner را عوض کن.'
  },
  {
    id: 'raw-call-value', sev: 'Medium', title: 'فراخوانی سطح پایین با value',
    re: /\.(call|send|transfer)\s*\{value\s*:/,
    desc: 'ارسال اتر با call سطح پایین؛ بازگشت آن چک نشده و در معرض reentrancy است.',
    fix: 'از الگوی Checks-Effects-Interactions و reentrancy guard استفاده کنید.',
    exploit: 'call فقط true/false برمی‌گرداند؛ اگر false چک نشود، کاربر سکه‌هایش را از دست می‌دهد.'
  },
  {
    id: 'reentrancy', sev: 'Medium', title: 'ریسک Reentrancy',
    re: /\.(call|send|transfer)\s*\{?\s*value|\.call\s*\(/,
    desc: 'در جایی فراخوانی خارجی انجام شده؛ اگر با guard نباشد، امکان ورود مجدد وجود دارد.',
    fix: 'guard ضد ورود مجدد (nonReentrant) و ترتیب CEI را رعایت کنید.',
    exploit: 'قرارداد مهاجم با fallback() که همان تابع را دوباره صدا می‌زند، درون فراخوانی هدف قرار می‌گیرد. اگر state بعد از فراخوانی آپدیت می‌شود = برداشت دوباره.'
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
    fix: 'فقط جایی استفاده شود که سرریز ریاضی اثبات‌شده غیرممکن است.',
    exploit: 'درون بلاک‌های unchecked به دنبال عملگر - یا * با مقادیر کاربری باش؛ با مقدار مرزی (max uint / کوچک) تست کن.'
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
    fix: 'به 0.8.x ارتقا دهید.',
    exploit: 'با مقادیر نزدیک به max uint عملگرهای + - * را در توابع عمومی تست کن.'
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
  },
  {
    id: 'oracle-spot', sev: 'High', title: 'قیمت از اوراکل لحظه‌ای (بدون TWAP)',
    re: /\b(slot0|getReserves|price0CumulativeLast|price1CumulativeLast|observe\s*\(|consult\s*\(|currentPrice|getPrice\s*\()/,
    desc: 'قیمت به‌صورت لحظه‌ای از AMM خوانده می‌شود (slot0 / getReserves / observe). با فلش‌لون یا یک سواپ بزرگ قابل دستکاری است و داد و ستد را می‌توان غارت کرد.',
    fix: 'از TWAP (میانگین وزنی زمانی) با پنجره کافی یا اوراکل زنجیره‌ای مثل Chainlink استفاده کنید.',
    exploit: 'در PoC ذخایر pool را ۱۰۰x جابه‌جا کن (فلش‌لون) و نشان بده قیمت/پاداش/سقف سواپ با همان تغییر می‌کند.'
  },
  {
    id: 'amm-helper', sev: 'Medium', title: 'استفاده از helper قیمت AMM',
    re: /\b(getAmountOut|getAmountsOut|getAmountIn|getAmountsIn|getAmountOutMin|quote\s*\()/,
    desc: 'محاسبه خروجی سواپ به‌صورت لحظه‌ای بر اساس ذخایر pool انجام می‌شود. اگر ورودی‌ها قابل دستکاری باشند یا خروجی حداقلی (slippage) نگیرد، ریسک MEV/ساندویچ دارد.',
    fix: 'حداقل خروجی و deadline بگذارید و در صورت امکان از TWAP استفاده کنید.',
    exploit: 'تراکنش قربانی را با ربات ساندویچ (خرید قبل + فروش بعد) جلو بزن؛ اگر مقدار ورودی بر پایه قیمت لحظه‌ای است، قیمت را جابه‌جا کن.'
  },
  {
    id: 'rounding-truncation', sev: 'Low', title: 'گرد کردن/ترانکیت در محاسبات (ضرب-تقسیم)',
    re: /\*\s*[^;\n]*\s*\/\s*\w+/,
    desc: 'محاسبات `x * y / z` به سمت پایین گرد می‌شوند. با مقادیر کوچک، ذره‌های (dust) به نفع یک طرف جمع می‌شوند. جهت گرد کردن و طرفِ سودبرنده را بررسی کن.',
    fix: 'جهت گرد کردن را به سمت ضررِ طرف دارای امتیاز تنظیم کنید یا دقت را بالا ببرید.',
    exploit: 'عملیات را با مقدار ۱ وئی بارها (تکرار/حلقه) اجرا کن و اختلاف جمع‌شده نزد هر طرف را حساب کن.'
  },
  {
    id: 'division-before-mul', sev: 'Medium', title: 'تقسیم قبل از ضرب (از دست رفتن دقت)',
    re: /\b\w+\s*\/\s*\w+\s*\*\s*\w+/,
    desc: 'الگوی `x / y * z` اول تقسیم می‌کند و دقت را از دست می‌دهد. در محاسبات سهام/نرخ/پاداش می‌تواند ذره‌ها را به نفع یک طرف جمع کند.',
    fix: 'ابتدا ضرب و بعد تقسیم کنید.',
    exploit: 'با مقادیر کوچک (۱..۱۰) محاسبه را دستی بازتولید کن؛ اگر گرد کردن به نفع مهاجم است، در PoC تکرارش کن.'
  },
  {
    id: 'sig-replay', sev: 'Medium', title: 'بازیابی امضا (ecrecover) — ریسک replay',
    fn: (src) => {
      const m = /\becrecover\s*\(/g.exec(src);
      if (!m) return null;
      const guarded = /\b(nonce|deadline|expiry|expires|isUsed|used|consumed|DOMAIN_SEPARATOR|domainSeparator)\b/i.test(src);
      return { index: m.index, sev: guarded ? 'Info' : 'Medium' };
    },
    desc: 'امضا با ecrecover بازیابی می‌شود؛ اگر nonce/deadline/domain-separator نداشته باشد، همان امضا را می‌توان چند بار (replay) استفاده کرد.',
    fix: 'nonce یکتا، deadline، و domain separator (EIP-712) اضافه کنید.',
    exploit: 'یک امضای معتبر را دوباره submit کن (همان تراکنش با همان پارامترها)؛ اگر دوباره پذیرفته شد = replay.'
  },
  {
    id: 'unbounded-loop', sev: 'Medium', title: 'حلقه بدون محدودیت روی آرایه ذخیره‌سازی',
    fn: (src) => {
      const re = /\bfor\s*\(([^;]*);\s*(\w+)\s*<\s*([A-Za-z_]\w*)\s*\.\s*length\s*;/g;
      let m;
      while ((m = re.exec(src))) {
        if (STORAGE_ARRAY.test(m[3])) return { index: m.index };
      }
      return null;
    },
    desc: 'حلقه‌ای روی آرایه ذخیره‌سازی که می‌تواند توسط کاربران بزرگ شود — هر عنصر باعث gas بیشتر می‌شود و تابع ممکن است gas-out (DoS) کند.',
    fix: 'با pagination یا ساختار index/bool کار کنید، نه آرایه خطی.',
    exploit: 'با چند تراکنش ارزان آرایه را هزاران عنصر کن و بعد تابعِ حلقه‌زن را صدا بزن؛ اگر out of gas شد = DoS.'
  },
  {
    id: 'unbounded-push', sev: 'Low', title: 'push بدون سقف روی آرایه ذخیره‌سازی',
    fn: (src) => {
      const re = /\b([A-Za-z_]\w*)\s*\.\s*push\s*\(/g;
      let m;
      while ((m = re.exec(src))) {
        if (STORAGE_ARRAY.test(m[1])) return { index: m.index };
      }
      return null;
    },
    desc: 'آرایه ذخیره‌سازی بدون سقف با push رشد می‌کند — با تراکنش‌های ارزان می‌توان آن را آب‌پر کرد (griefing).',
    fix: 'سقف/قیمت برای push یا ساختار mapping+array index بگذارید.'
  },
  {
    id: 'initialize-unguarded', sev: 'High', title: 'initialize بدون گارد یک‌بار-اجرا',
    fn: (src) => {
      const m = /\binitialize\s*\(/g.exec(src);
      if (!m) return null;
      if (/\binitializer\b/.test(src)) return { index: m.index, sev: 'Info' };
      return { index: m.index, sev: 'High' };
    },
    desc: 'تابع initialize وجود دارد ولی modifier یک‌بار-اجرا (initializer) ندارد. هر کس می‌تواند بعد از deploy دوباره آن را صدا بزند و مالک/state را عوض کند.',
    fix: 'به الگوی OpenZeppelin Initializable (modifier initializer) و constructor-of-implementation برگردید.',
    exploit: 'بعد از deploy، از یک آدرس دلخواه `initialize(...)` را صدا بزن؛ اگر state/owner تغییر کرد و قبلاً مقداردهی شده بود = باگ.'
  },
  {
    id: 'no-slippage-deadline', sev: 'Medium', title: 'بدون محافظت سلیپج/ددلاین در سواپ',
    fn: (src) => {
      const swap = /\b(swap|exactInput|exactInputSingle|exactOutput|exactOutputSingle|addLiquidity|removeLiquidity|zap|buy\s*\(|sell\s*\(|close|exercise)\b/i.test(src);
      if (!swap) return null;
      const protects = /\b(minAmount|minOut|minReturn|minReceived|minAssets|minLp|slippage|amountOutMin|amountOutMinimum|amountInMax|maxAmountIn|deadline|expiry)\b/i.test(src);
      if (protects) return null;
      return { index: src.search(/\b(swap|buy\s*\(|sell\s*\(|addLiquidity)/i) };
    },
    desc: 'عملیات سواپ/نقدینگی بدون حداقل خروجی و deadline انجام می‌شود — قربانی با ساندویچ/MEV قیمت را از دست می‌دهد.',
    fix: 'پارامتر amountOutMin و deadline (بازار بسته) اضافه کنید.',
    exploit: 'تراکنش کاربر را در ممپول جلو بزن (sandwich): ربات قبل از آن بسته به حجم ۱۰۰x می‌خرد و بعد از آن می‌فروشد؛ اگر خروجی حداقلی نباشد، کاربر ضرر می‌کند.'
  },
  {
    id: 'hidden-owner', sev: 'High', title: 'چند انتساب مالکیت / backdoor احتمالی',
    fn: (src) => {
      const direct = src.match(/\bowner\s*=\s*msg\.sender/g) || [];
      const assigns = src.match(/\b(owner|admin|governance|pendingOwner|newOwner)\s*=\s*(msg\.sender|address\([^)]*\))/g) || [];
      if (direct.length >= 2 || assigns.length >= 3) {
        return { index: src.indexOf(direct[0] || assigns[0]) };
      }
      return null;
    },
    desc: 'مالکیت در چند جا و شاید خارج از constructor انتساب می‌شود — می‌تواند backdoor یا مالک دوم باشد. هر انتساب را خط‌به‌خط بررسی کنید.',
    fix: 'مالکیت فقط در constructor و از طریق تابع‌های استاندارد (transferOwnership) عوض شود.',
    exploit: 'آدرس‌های داخل انتساب‌های مالکیت را در etherscan چک کن؛ اگر آدرسی غیر از deployer است، احتمالا مالک پنهان (rug) است.'
  },
  {
    id: 'extcodesize', sev: 'Low', title: 'چک اندازه کد (extcodesize)',
    re: /\bextcodesize\s*\(/,
    desc: 'چک `code.length == 0` برای تشخیص EOA قابل دور زدن است: در همان تراکنش از یک قرارداد در حال ساخت صدا می‌زنید.',
    fix: 'از این چک فقط به‌همراه مکانیزم‌های دیگر استفاده کنید.',
    exploit: 'در PoC تابع را از constructor یک قرارداد دیگر صدا بزن (قبل از اینکه کد deploy شود).'
  },
  {
    id: 'approve-race', sev: 'Low', title: 'تغییر allowance (race)',
    re: /\bapprove\s*\(/,
    desc: 'تغییر allowance از مقدار قبلی به مقدار جدید قابل رقابت است (race)؛ کاربر قدیمی می‌تواند قبل از approve جدید، از allowance قبلی استفاده کند.',
    fix: 'از increaseAllowance/decreaseAllowance استفاده کنید.'
  },
  {
    id: 'receive-fallback', sev: 'Info', title: 'قرارداد اتر می‌گیرد ولی receive/fallback ندارد',
    fn: (src) => {
      const getsEth = /msg\.value|payable\s*\([^)]*\)|\.call\s*\{value/i.test(src);
      if (!getsEth) return null;
      if (!/\breceive\s*\(/.test(src) && !/\bfallback\s*\(/.test(src)) return { index: 0 };
      return null;
    },
    desc: 'قرارداد اتر دریافت می‌کند (msg.value / payable) ولی تابع receive/fallback ندارد — اتر ارسالی مستقیم ممکن است در قرارداد قفل شود.',
    fix: 'در صورت نیاز receive() و مسیر برداشت اتر اضافه کنید.'
  }
];

function externalCallMap(source) {
  const chunks = source.split(/\n\s*function\s+/);
  const nonGuarded = [];
  const guarded = [];
  chunks.slice(1).forEach(chunk => {
    const name = (chunk.match(/^([A-Za-z_]\w*)/) || [])[1];
    if (!name) return;
    const hasCall = /\.(call|send|transfer)\b|\.call\s*\{?\s*value/i.test(chunk);
    if (!hasCall) return;
    const g = /nonReentrant|ReentrancyGuard/.test(chunk);
    (g ? guarded : nonGuarded).push(name);
  });
  return { nonGuarded, guarded };
}

function functionChunks(source) {
  const chunks = source.split(/\n\s*function\s+/);
  const out = [];
  chunks.slice(1).forEach(chunk => {
    const name = (chunk.match(/^([A-Za-z_]\w*)/) || [])[1];
    if (name) out.push({ name, body: chunk });
  });
  return out;
}

// Economic / logic-invariant rules: accounting, rounding direction, share math,
// fee-on-transfer mismatch, pair-based buy/sell split, upgradeable storage.
function economicScan(source) {
  const findings = [];
  const clean = stripComments(source);
  const chunks = functionChunks(clean);
  const push = (id, sev, title, detail, fix, exploit, index) => {
    findings.push({ id, sev, title, detail, fix, exploit, line: findLine(clean, index), kind: 'static' });
  };

  // E1 — deposit accounting via transferFrom can break with fee-on-transfer tokens.
  const ftChunks = chunks.filter(c => /\.transferFrom\s*\(/.test(c.body));
  if (ftChunks.length) {
    push('fee-on-transfer-mismatch', 'Medium', 'دریافت توکن با transferFrom — ریسک توکن کارمزددار/rebasing',
      'توابع ' + ftChunks.map(c => c.name).join(', ') + ' توکن را با transferFrom می‌گیرند ولی مبلغ ثبت‌شده همان amount است. با توکن‌های fee-on-transfer یا rebasing مقدار واقعی دریافتی کمتر/بیشتر از amount است و حسابداری به‌هم می‌خورد (سهم‌ها بیشتر از دارایی واقعی).',
      'بعد از transferFrom، بالانس واقعی را با balanceOf بخوانید یا delta-balance بگیرید.',
      'در PoC با یک توکن کارمزددار (مثل STA/PAXG-style) سپرده‌گذاری کن و نشان بده سهم/اعتبارِ ثبت‌شده بیشتر از موجودی واقعی است.', ftChunks[0].body.indexOf('transferFrom'));
  }

  // E2 — share/asset math with truncation in deposit/withdraw.
  const shareChunks = chunks.filter(c => /(deposit|mint|stake|enter|convertToShares|previewDeposit|withdraw|redeem|claim)/i.test(c.name) && /\*\s*[^;\n]*\/\s*\w+/.test(c.body));
  if (shareChunks.length) {
    push('share-math-rounding', 'Medium', 'گرد کردن در محاسبه سهم/دارایی (deposit/withdraw)',
      'محاسبه سهم در توابع ' + shareChunks.map(c => c.name).join(', ') + ' با ضرب-تقسیم انجام می‌شود. گرد کردن به سمت پایین در آستانه‌های کوچک = از دست رفتن دارایی کاربر یا ریسک first-depositor/inflation attack.',
      'جهت گرد کردن را به سمت ضررِ پروتکل تنظیم کنید و حداقل سپرده/سهم بگذارید.',
      'اولین depositor شو، سپس مقدار بسیار کوچک دیگر سپرده کن؛ اگر سهم او ۰ شد یا rounding به نفع او جمع شد = inflation/dust.', shareChunks[0].body.indexOf('*'));
  }

  // E3 — accounting based on full self-balance is donation-manipulable.
  const balChunks = chunks.filter(c => /(deposit|withdraw|redeem|claim|reward|stake|interest|convertToAssets)/i.test(c.name) && /balanceOf\s*\(\s*address\s*\(\s*this\s*\)|\.balance\b/.test(c.body));
  if (balChunks.length) {
    const idx = balChunks[0].body.indexOf('balanceOf');
    push('self-balance-accounting', 'Medium', 'حسابداری بر پایه بالانس کامل قرارداد',
      'توابع ' + balChunks.map(c => c.name).join(', ') + ' بر اساس balanceOf(address(this)) یا .balance حساب می‌کنند. یک donation مستقیم می‌تواند ارزش محاسباتی را جابه‌جا کند (griefing)، پاداش را منحرف کند یا قیمت سهم را دستکاری کند.',
      'مقدار را صرفاً از delta (قبل/بعد) یا پارامتر ورودی محاسبه کنید، نه بالانس کامل.',
      'یک مقدار کوچک توکن/اتر مستقیم به قرارداد بفرست و ببین سهم/پاداش/نرخ عوض می‌شود.', idx >= 0 ? idx : balChunks[0].body.indexOf('.balance'));
  }

  // E4 — ERC20 return value unchecked (false-success tokens).
  const retChunks = chunks.filter(c => /\.(transfer|transferFrom|approve)\s*\(/.test(c.body) && !/require|if\s*\(|\.ok\b|\bok\b/.test(c.body));
  if (retChunks.length) {
    push('unchecked-erc20-return', 'Low', 'بازگشت توکن چک نشده (false success)',
      'توابع ' + retChunks.map(c => c.name).join(', ') + ' نتیجه transfer/transferFrom/approve را چک نمی‌کنند. برای توکن‌های غیراستاندارد که false برمی‌گردانند، شکست بی‌صدا = خطای حسابداری.',
      'از SafeERC20 استفاده کنید یا require(ok) بگذارید.',
      'در PoC با توکنی که transfer را false برمی‌گرداند نشان بده تراکنش «موفق» ثبت می‌شود ولی توکن جابه‌جا نشده.', retChunks[0].body.indexOf('.transfer'));
  }

  // E5 — separate buy/sell tax but no pair comparison = sell-tax bypass.
  const hasPair = /\b\w*pair\w*\b/.test(clean);
  const hasBuySell = /\b(buyTax|sellTax|buyTaxBps|sellTaxBps|buyFee|sellFee|taxOnBuy|taxOnSell|buyTaxPercent|sellTaxPercent)\b/i.test(clean);
  if (hasPair && hasBuySell && !/\b\w*pair\w*\s*(==|!=|>=|<=|>|<)|==\s*\w*pair|!=\s*\w*pair/.test(clean)) {
    push('buy-sell-pair-missing', 'Medium', 'تفکیک خرید/فروش بر اساس pair پیاده نشده',
      'قرارداد هم مالیات جدا برای خرید/فروش دارد و هم آدرس pair، ولی هیچ مقایسه‌ای با pair در کد دیده نمی‌شود. فروشندگان می‌توانند با انتقال مستقیم (بدون عبور از صرافی) از مالیات فروش فرار کنند یا مالیات اشتباه گرفته شود.',
      'در مسیر انتقال، `to == pair` (فروش) و `from == pair` (خرید) را دقیق تفکیک کنید.',
      'در PoC از یک آدرس معمولی چند انتقال بده و ببین مالیات فروش اعمال می‌شود یا نه.', clean.indexOf('pair'));
  }

  // E6 — upgradeable without storage gap.
  if (/\b(initializer|upgradeTo|upgradeToAndCall|_authorizeUpgrade)\b/.test(clean) && !/\b__gap\b/.test(clean)) {
    push('upgradeable-gap', 'Info', 'بدون storage gap در قرارداد آپگریدپذیر',
      'قرارداد الگوی آپگرید دارد ولی __gap دیده نمی‌شود. افزودن متغیر جدید در نسخه بعدی، storage را جابه‌جا می‌کند (storage collision) و state را خراب می‌کند.',
      'یک آرایه __gap (مثلاً ۵۰ اسلات) در انتهای storage بگذارید.', '', clean.indexOf('upgradeTo') >= 0 ? clean.indexOf('upgradeTo') : clean.indexOf('initializer'));
  }

  // E7 — LP liquidity not visibly locked.
  if (/\baddLiquidity\b/.test(clean) && !/\block|_lock\b/.test(clean)) {
    push('liquidity-unlocked', 'Info', 'نقدینگی (LP) — قفل دیده نمی‌شود',
      'قرارداد addLiquidity دارد ولی مکانیزم قفل LP دیده نمی‌شود. اگر توکن LP نزد مالک بماند و قفل نباشد، ریسک rug (حذف نقدینگی) دارد.',
      'توکن LP را قفل/بسوزانید یا به یک آدرس قفل (timelock) بدهید.', '', clean.indexOf('addLiquidity'));
  }

  return findings;
}

// ---------- AST expert analyzer (solc legacy AST from standard JSON) ----------
// Walks the actual parse tree (not regexes) to detect real CEI violations,
// per-function access control, variable shadowing and attack-surface data.
function astWalk(root, visit) {
  const seen = new Set();
  (function rec(n) {
    if (!n || typeof n !== 'object' || seen.has(n)) return;
    seen.add(n);
    visit(n);
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) { for (const x of v) rec(x); }
      else if (v && typeof v === 'object') rec(v);
    }
  })(root);
}

function srcStart(srcStr) {
  const m = /^(\d+)/.exec(String(srcStr));
  return m ? +m[1] : 0;
}

function srcSlice(source, srcStr) {
  const m = /^(\d+):(\d+)/.exec(String(srcStr));
  if (!m) return '';
  return source.substr(+m[1], +m[2]);
}

function nodeTypeName(tn) {
  if (!tn) return '';
  switch (tn.nodeType) {
    case 'ElementaryTypeName': return tn.name;
    case 'ArrayTypeName': return nodeTypeName(tn.baseType) + '[]';
    case 'Mapping': return 'mapping';
    case 'UserDefinedTypeName': return tn.name || (tn.pathNode || []).map(p => p.name || '').join('.');
    default: return tn.name || tn.nodeType || '';
  }
}

function isStateRef(node, stateNames) {
  if (!node || !node.nodeType) return false;
  if (node.nodeType === 'Identifier') return stateNames.has(node.name);
  if (node.nodeType === 'IndexAccess') return isStateRef(node.baseExpression || node.base, stateNames);
  if (node.nodeType === 'MemberAccess') return isStateRef(node.expression, stateNames);
  return false;
}

const EXTCALL_MEMBERS = new Set(['call', 'send', 'transfer', 'delegatecall', 'staticcall', 'callcode']);
function extCallMember(n) {
  if (n.nodeType !== 'FunctionCall' || !n.expression) return null;
  let e = n.expression;
  if (e.nodeType === 'FunctionCallOptions') e = e.expression;
  if (e && e.nodeType === 'MemberAccess' && EXTCALL_MEMBERS.has(e.memberName)) return e.memberName;
  return null;
}
function isExtCallNode(n) {
  return extCallMember(n) !== null;
}
function extCallHasValue(n) {
  if (n.nodeType !== 'FunctionCall') return false;
  if (n.value) return true;
  const e = n.expression;
  if (e && e.nodeType === 'FunctionCallOptions' && e.options && e.options.value) return true;
  return false;
}

function collectStateVars(contractNode) {
  const vars = [];
  (contractNode.nodes || []).forEach(n => {
    if (n.nodeType === 'StateVariableDeclaration') {
      (n.variables || []).forEach(v => vars.push({ name: v.name, type: nodeTypeName(v.typeName), visibility: v.visibility || 'internal' }));
    } else if (n.nodeType === 'VariableDeclaration' && (n.isStateVar === true || n.stateVariable === true)) {
      vars.push({ name: n.name, type: nodeTypeName(n.typeName), visibility: n.visibility || 'internal' });
    }
  });
  return vars;
}

function fnModifierNames(fnNode) {
  return (fnNode.modifiers || []).map(m => {
    const mn = m.modifierName;
    return (mn && mn.name) || m.name || '';
  }).filter(Boolean);
}

function fnAccessGuard(source, fnNode) {
  let guard = '';
  astWalk(fnNode.body, n => {
    if (guard) return;
    if (n.nodeType === 'FunctionCall' && n.expression && n.expression.nodeType === 'Identifier' &&
        (n.expression.name === 'require' || n.expression.name === 'assert')) {
      const arg0 = (n.arguments || [])[0];
      if (arg0 && arg0.nodeType !== 'Literal') guard = srcSlice(source, arg0.src).replace(/\s+/g, ' ').trim();
    }
  });
  return guard;
}

function fnEvents(fnNode, stateNames) {
  const calls = [];
  const writes = [];
  astWalk(fnNode.body, n => {
    if (n.nodeType === 'FunctionCall') {
      if (isExtCallNode(n)) calls.push({ off: srcStart(n.src), value: extCallHasValue(n) });
      if (n.expression && n.expression.nodeType === 'MemberAccess' && n.expression.memberName === 'push' &&
          isStateRef(n.expression.expression, stateNames)) {
        writes.push({ off: srcStart(n.src), kind: 'push' });
      }
    } else if (n.nodeType === 'Assignment' && isStateRef(n.leftHandSide, stateNames)) {
      writes.push({ off: srcStart(n.src), kind: 'assign' });
    } else if (n.nodeType === 'UnaryOperation' && (n.operator === '++' || n.operator === '--') && isStateRef(n.subExpression, stateNames)) {
      writes.push({ off: srcStart(n.src), kind: 'unary' });
    }
  });
  const byOff = (a, b) => a.off - b.off;
  calls.sort(byOff); writes.sort(byOff);
  return { calls, writes };
}

function fnShadowed(stateNames, fnNode) {
  const out = [];
  ((fnNode.parameters && fnNode.parameters.parameters) || []).forEach(p => {
    if (p.name && stateNames.has(p.name) && out.indexOf(p.name) < 0) out.push(p.name);
  });
  astWalk(fnNode.body, n => {
    if (n.nodeType === 'VariableDeclarationStatement') {
      (n.variables || []).forEach(v => {
        if (v.name && stateNames.has(v.name) && out.indexOf(v.name) < 0) out.push(v.name);
      });
    }
  });
  return out;
}

function isPayableFn(fnNode) {
  return fnNode.stateMutability === 'payable' || fnNode.isPayable === true ||
    (fnNode.modifiers || []).some(m => (m.modifierName && m.modifierName.name) === 'payable');
}

export function astAnalyze(ast, source) {
  const findings = [];
  const contracts = [];
  const push = (sev, title, detail, fix, exploit, index, id) => {
    findings.push({ id: id || 'ast', sev, title, detail, fix, exploit, line: findLine(source, index), kind: 'ast' });
  };

  if (!ast || !ast.nodes) return { findings, contracts };

  const upgradeable = /initializer|upgradeTo|_authorizeUpgrade|delegatecall/i.test(source);

  ast.nodes.forEach(suNode => {
    if (!suNode || suNode.nodeType !== 'ContractDefinition') return;
    const stateVars = collectStateVars(suNode);
    const stateNames = new Set(stateVars.map(v => v.name));
    const fns = [];
    (suNode.nodes || []).forEach(n => {
      if (n.nodeType !== 'FunctionDefinition') return;
      fns.push(n);
      const name = n.name || '';
      const isEntry = n.visibility === 'external' || n.visibility === 'public';
      const isStateMutating = n.stateMutability !== 'view' && n.stateMutability !== 'pure';

      // CEI: external call then a state write, without a reentrancy guard.
      if (isEntry && isStateMutating) {
        const { calls, writes } = fnEvents(n, stateNames);
        const mods = fnModifierNames(n);
        if (calls.length && writes.length) {
          const firstCall = calls[0];
          const lateWrites = writes.filter(w => w.off > firstCall.off);
          const guarded = mods.some(m => /nonReentrant|guard|protected|pausable/i.test(m));
          if (lateWrites.length && !guarded) {
            const sev = (/(withdraw|redeem|claim|pay|buy|sell|swap|execute|collect|harvest|unstake|release|mint)/i.test(name) || calls.some(c => c.value)) ? 'High' : 'Medium';
            push(sev, 'شکستن CEI در تابع ' + name + ' (نوشتن state بعد از فراخوانی خارجی)',
              'در تابع ' + name + ' ابتدا فراخوانی خارجی (call/send/transfer) انجام می‌شود و سپس ' + lateWrites.length + ' نوشتنِ state می‌آید، بدون modifier ضد ورود مجدد. این دقیقاً الگوی Reentrancy است.',
              'همه به‌روزرسانی‌های state را قبل از فراخوانی خارجی منتقل کنید یا nonReentrant اضافه کنید.',
              'قرارداد مهاجم با fallback() همان تابع را دوباره صدا می‌زند؛ اگر برداشت دوم موفق شد، اثر اقتصادی را در PoC ثابت کن.',
              lateWrites[0].off, 'ast-cei-' + name);
          }
        }
      }

      // Per-function access control for privileged-looking functions.
      if (isEntry && isStateMutating && PRIVILEGED.test(name)) {
        const mods = fnModifierNames(n);
        const guard = fnAccessGuard(source, n);
        if (!mods.length && !guard) {
          push('Medium', 'تابع ویژه بدون محافظ دسترسی ظاهری: ' + name + ' (تحلیلگر AST)',
            'تابع ' + name + ' (نام وابسته به نقش) هیچ modifier و هیچ require/assert بر msg.sender ندارد. اگر مجاز به فراخوانی عمومی نیست، باگ کنترل دسترسی است.',
            'modifier فقط‌نقش یا require(msg.sender == ...) اضافه کنید.',
            'از یک EOA دلخواه (نه مالک) تابع را صدا بزن؛ بدون revert اجرا شد = اثبات. سپس اثر اقتصادی را بسنج.',
            srcStart(n.src), 'ast-acl-' + name);
        }
      }

      // Variable shadowing.
      const shadowed = fnShadowed(stateNames, n);
      if (shadowed.length) {
        push('Low', 'سایه‌اندازی متغیر در تابع ' + name + ': ' + shadowed.join(', '),
          'پارامتر/متغیر محلی ' + shadowed.join(', ') + ' نام یک متغیر state را تکرار می‌کند. خوانایی و امنیت را به خطر می‌اندازد (اشتباه در ارجاع به state).',
          'نام متغیر محلی را تغییر دهید.',
          '', srcStart(n.src), 'ast-shadow-' + name);
      }
    });

    contracts.push({
      name: suNode.name || 'Contract',
      contractKind: suNode.contractKind || 'contract',
      stateVars: stateVars.map(v => v.name + ': ' + v.type),
      functions: fns.filter(f => f.visibility === 'external' || f.visibility === 'public').map(f => f.name || ''),
      payableFunctions: fns.filter(isPayableFn).map(f => f.name || ''),
      upgradeable
    });
  });

  return { findings, contracts };
}

export function attackSurface(ast, source) {
  const surface = { contracts: [], roles: [], assets: [], entrypoints: [] };
  if (!ast || !ast.nodes) return surface;
  const seenRoles = new Set();
  const seenAssets = new Set();
  const addRole = (name, from) => {
    if (seenRoles.has(name)) return;
    seenRoles.add(name);
    surface.roles.push({ name, from });
  };
  const addAsset = (name, desc) => {
    if (seenAssets.has(name)) return;
    seenAssets.add(name);
    surface.assets.push({ name, desc });
  };
  ast.nodes.forEach(suNode => {
    if (!suNode || suNode.nodeType !== 'ContractDefinition') return;
    const stateVars = collectStateVars(suNode);
    const stateNames = new Set(stateVars.map(v => v.name));
    const entrypoints = [];
    let hasPayable = false;
    let transfersToken = false;
    (suNode.nodes || []).forEach(n => {
      if (n.nodeType !== 'FunctionDefinition') return;
      const name = n.name || '';
      const isEntry = n.visibility === 'external' || n.visibility === 'public';
      if (isPayableFn(n)) hasPayable = true;
      if (isEntry && n.stateMutability !== 'view' && n.stateMutability !== 'pure') {
        const mods = fnModifierNames(n);
        const guard = fnAccessGuard(source, n);
        mods.forEach(m => {
          const r = /^only(Owner|Admin|Operator|Minter|Governance|Pauser|Vault|Role)/i.exec(m);
          if (r) addRole(r[1] || m, 'modifier ' + m);
        });
        if (guard && /msg\.sender/.test(guard)) addRole('owner-check', 'require: ' + guard);
        entrypoints.push({
          name, stateMutability: n.stateMutability,
          mods, guard,
          args: ((n.parameters && n.parameters.parameters) || []).map(p => nodeTypeName(p.typeName) + (p.name ? ' ' + p.name : ''))
        });
      }
      astWalk(n.body, node => {
        if (node.nodeType === 'FunctionCall' && node.expression && node.expression.nodeType === 'MemberAccess' &&
            (node.expression.memberName === 'transfer' || node.expression.memberName === 'transferFrom')) {
          transfersToken = true;
        }
      });
    });
    surface.contracts.push({
      name: suNode.name || 'Contract', contractKind: suNode.contractKind || 'contract',
      stateVars: stateVars.map(v => v.name + ': ' + v.type), entrypoints, hasPayable, transfersToken
    });
    if (hasPayable) addAsset('ETH', 'قرارداد payable — اتر دریافت می‌کند');
    if (transfersToken) addAsset('ERC-20', 'توکن‌ها با transfer/transferFrom جابه‌جا می‌شوند');
    if (stateNames.has('owner')) addAsset('Ownership', 'متغیر state با نام owner وجود دارد');
  });
  return surface;
}

export function staticScan(source) {
  const findings = [];
  const clean = stripComments(source);
  STATIC_RULES.forEach(rule => {
    let hit = null;
    if (rule.fn) {
      const r = rule.fn(clean);
      if (r) hit = { index: r.index, sev: r.sev || rule.sev };
    } else {
      const src = rule.raw ? source : clean;
      const m = src.match(rule.re);
      if (m) hit = { index: m.index, sev: rule.sev };
    }
    if (hit) {
      findings.push({
        id: rule.id,
        sev: hit.sev,
        title: rule.title,
        detail: rule.desc,
        fix: rule.fix,
        exploit: rule.exploit || '',
        line: findLine(clean, hit.index),
        kind: 'static'
      });
    }
  });

  // Reentrancy guard cross-check + function-level external-call map.
  const hasGuard = /nonReentrant|ReentrancyGuard|locked\s*=/i.test(clean);
  const hasExternalCall = /\.(call|send|transfer)\b|\.call\s*\{?value/i.test(clean);
  if (hasExternalCall && !hasGuard) {
    findings.push({
      id: 'reentrancy-guard', sev: 'Medium', title: 'نداشتن guard ضد ورود مجدد',
      detail: 'فراخوانی خارجی وجود دارد ولی هیچ nonReentrant/ReentrancyGuard دیده نمی‌شود.',
      fix: 'به توابع دارای فراخوانی خارجی، modifier ضد ورود مجدد اضافه کنید.',
      exploit: 'اگر تابعِ فراخوانی‌کننده خارجی، state را بعد از call به‌روزرسانی می‌کند، با fallback مهاجم دو بار برداشت کن.',
      line: 0, kind: 'static'
    });
  }
  const map = externalCallMap(clean);
  if (map.nonGuarded.length) {
    findings.push({
      id: 'extcall-no-guard', sev: 'Medium', title: 'فراخوانی خارجی بدون guard در توابع: ' + map.nonGuarded.join(', '),
      detail: 'این توابع تماس خارجی دارند و nonReentrant ندارند: ' + map.nonGuarded.join(', ') + '. اگر با مقدار/کنترل کاربر کار کنند، ریسک Reentrancy جدی است.',
      fix: 'guard اضافه کنید یا ترتیب CEI را رعایت کنید.',
      exploit: 'قرارداد مهاجم با fallback() که همان تابع را دوباره صدا می‌زند؛ اگر دو بار برداشت موفق شد = reentrancy.',
      line: 0, kind: 'static'
    });
  }
  if (map.guarded.length) {
    findings.push({
      id: 'extcall-guarded', sev: 'Info', title: 'فراخوانی خارجی با guard',
      detail: 'توابع دارای فراخوانی خارجی با nonReentrant: ' + map.guarded.join(', ') + '. همچنان ترتیب CEI را بررسی کنید.',
      fix: '',
      line: 0, kind: 'static'
    });
  }
  findings.push(...economicScan(source));
  return findings;
}

// ---------- Dynamic probes (deploy + attempt attacks in the browser EVM) ----------
const PRIVILEGED = /^(set|update|add|remove|withdraw|rescue|claim|mint|pause|setPaused|transferOwnership|renounceOwnership|forceUnlock|setBlacklisted|setWhitelisted|setExcluded|setWhaleExempt|setMaxTx|setTax|setBuySellTax|setMarketingWallet|setPair|setAntiWhale|emergency|kill|destroy|admin|governance|config)/i;
// Functions that are public by design — calling them proves nothing.
const BENIGN = /^(transfer|transferFrom|approve|increaseAllowance|decreaseAllowance|burn|burnFrom|setApprovalForAll|receive|fallback)$/i;

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

// Call a view/function and decode the returned uint256 (offset 0).
async function readUint(vm, from, to, data) {
  const r = await vm.evm.runCall({
    caller: Address.fromString(from), to,
    data, gasLimit: 0xFFFFFFFFn, gasPrice: 1n, value: 0n
  });
  const ret = r.execResult && r.execResult.returnValue;
  if (!ret) return 0n;
  const bytes = Buffer.isBuffer(ret) ? ret : Buffer.from(ret);
  const hex = bytes.toString('hex').padStart(64, '0').slice(0, 64);
  return BigInt('0x' + hex);
}

async function newVM(bytecode) {
  const common = Common.custom({ chainId: 1 }, { hardfork: 'cancun' });
  const vm = await VM.create({ common });
  const addr = await deployContract(vm, bytecode);
  return { vm, addr };
}

export async function runSecurityTests(abi, bytecode, source) {
  const started = Date.now();
  const probes = [];
  const record = (name, attackSucceeded, sev, detail, exploit) => {
    probes.push({
      name, kind: 'dynamic',
      secure: !attackSucceeded,
      sev,
      detail: attackSucceeded
        ? '⚠ حمله موفق شد: ' + detail
        : 'حمله‌مقابل دفع شد: ' + detail,
      exploit: exploit || ''
    });
  };

  const { vm, addr } = await newVM(bytecode);
  if (!addr) {
    return { probes: [{ name: 'deploy', kind: 'dynamic', secure: false, sev: 'Critical', detail: 'قرارداد deploy نشد.', exploit: '' }], durationMs: Date.now() - started };
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
    record('کنترل دسترسی توابع ویژه', true, 'High', 'توابع ' + exploited.join(', ') + ' برای هر کس قابل فراخوانی هستند (بدون revert از سمت غیرمالک).', 'در گزارش نهایی، برای هر تابع این‌جا را ثابت کن: آدرس غیرمالک، همان آرگومان‌ها. شدت بر اساس اثر (برداشت/تغییر state/ربودن) تعیین می‌شود.');
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

  // 14. Generic authorization scan: every other state-changing function.
  // Runs in a fresh VM so a state-corrupting call cannot skew other probes.
  try {
    const { vm: vm2, addr: addr2 } = await newVM(bytecode);
    const candidates = abi.filter(f => f.type === 'function' && !isView(f) &&
      !PRIVILEGED.test(f.name) && !BENIGN.test(f.name) &&
      !/^(renounceOwnership|kill|destroy|die|selfdestruct)$/i.test(f.name));
    const open = [];
    for (const f of candidates) {
      let values;
      try {
        values = (f.inputs || []).map((inp, i) => guessArg(inp.type, i));
      } catch (e) { continue; }
      let r;
      try {
        r = await call(vm2, ATTACKER, addr2, encodeCall(f, values));
      } catch (e) { continue; }
      if (!r.reverted) open.push(f.name);
    }
    if (open.length) {
      record('کنترل دسترسی (اسکن کامل همه توابع)', true, 'High',
        'توابع ' + open.join(', ') + ' از طرف غیرمالک بدون revert اجرا شدند. بررسی کنید عمدی/مجازاند یا باگ (چون آرگومان حدسی است، اگر عمدی‌اند نادیده بگیرید).',
        'برای هر تابع موفق، سناریوی واقعی را بساز (مثلاً همان‌ها را با آرگومان‌های درست از یک EOA دلخواه صدا بزن) و اثر آن روی state/وجوه را نشان بده.');
    } else {
      record('کنترل دسترسی (اسکن کامل همه توابع)', false, 'Info', 'هیچ تابع غیرآشکار دیگری از طرف غیرمالک اجرا نشد.');
    }
  } catch (e) {
    record('کنترل دسترسی (اسکن کامل همه توابع)', false, 'Info', 'اسکن کامل در این اجرا انجام نشد (' + e.message + ').');
  }

  // 15. initialize / init from attacker — fresh VM so ownership hijack cannot
  // corrupt the other probes.
  try {
    const initNames = ['initialize', 'init', 'initiate'];
    const initFn = abi.find(f => f.type === 'function' && initNames.includes(f.name.toLowerCase()) && !isView(f));
    if (initFn) {
      const { vm: vm3, addr: addr3 } = await newVM(bytecode);
      let values;
      try {
        values = (initFn.inputs || []).map((inp, i) => guessArg(inp.type, i));
      } catch (e) { values = []; }
      const r = await call(vm3, ATTACKER, addr3, encodeCall(initFn, values));
      record('فراخوانی دوباره initialize/init توسط هر کس', !r.reverted, 'Critical',
        !r.reverted ? 'تابع ' + initFn.name + ' از طرف غیرمالک بدون revert اجرا شد — ریسک ربایش مالکیت/تغییر state.' : 'initialize قابل فراخوانی از طرف غیرمالک نبود (محرمانه/تک‌بار).');
    } else {
      record('فراخوانی دوباره initialize/init', false, 'Info', 'تابع initialize در ABI دیده نشد.');
    }
  } catch (e) {
    record('فراخوانی دوباره initialize/init', false, 'Info', 'پروب initialize اجرا نشد (' + e.message + ').');
  }

  // 16. Token balance-conservation invariant: 50 tiny transfers must not leak
  // or create tokens. Runs on plain tokens (no tax/fee state) in a fresh VM.
  try {
    const hasTax = abi.some(f => /tax|fee/i.test(f.name));
    if (hasFn(abi, 'transfer') && hasFn(abi, 'balanceOf') && hasFn(abi, 'totalSupply') && !hasTax) {
      const { vm: vm4, addr: addr4 } = await newVM(bytecode);
      const trFrag = fragOf(abi, 'transfer');
      const balFrag = { name: 'balanceOf', inputs: [{ type: 'address' }] };
      const tsFrag = fragOf(abi, 'totalSupply');
      const supply0 = await readUint(vm4, OWNER, addr4, encodeCall(tsFrag, []));
      await call(vm4, OWNER, addr4, encodeCall(trFrag, [ATTACKER, 1000n]));
      const bA0 = await readUint(vm4, ATTACKER, addr4, encodeCall(balFrag, [ATTACKER]));
      const bO0 = await readUint(vm4, ATTACKER, addr4, encodeCall(balFrag, [OWNER]));
      for (let k = 0; k < 50; k++) {
        await call(vm4, ATTACKER, addr4, encodeCall(trFrag, [OWNER, 1n]));
      }
      const bA1 = await readUint(vm4, ATTACKER, addr4, encodeCall(balFrag, [ATTACKER]));
      const bO1 = await readUint(vm4, ATTACKER, addr4, encodeCall(balFrag, [OWNER]));
      const supply1 = await readUint(vm4, ATTACKER, addr4, encodeCall(tsFrag, []));
      const leaks = (bA0 + bO0) !== (bA1 + bO1);
      const supplyChanged = supply0 !== supply1;
      record('پایستگی توکن (حسابداری در انتقال‌های ریز)',
        leaks || supplyChanged, 'Medium',
        leaks || supplyChanged
          ? 'پس از ۵۰ انتقال ۱-وئی، مجموع بالانس‌ها یا عرضه تغییر کرد — نشتی، گرد کردن یا ضرر حسابداری در انتقال‌های ریز وجود دارد.'
          : 'پس از ۵۰ انتقال ۱-وئی مجموع بالانس‌ها و عرضه ثابت ماند — حسابداری پایستار است.');
    } else {
      record('پایستگی توکن', false, 'Info', 'این تست روی توکن‌های دارای مالیات/کارمزد یا بدون totalSupply/balanceOf اجرا نمی‌شود.');
    }
  } catch (e) {
    record('پایستگی توکن', false, 'Info', 'پروب پایستگی اجرا نشد (' + e.message + ').');
  }

  return { probes, durationMs: Date.now() - started };
}

// ---------- Report ----------
export function buildReport(source, abi, bytecode, staticFindings, dynamic) {
  const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const all = staticFindings.map(f => ({ ...f })).concat(dynamic.probes.map(p => ({
    id: 'dyn-' + p.name, sev: p.secure ? 'Info' : p.sev,
    title: p.name, detail: p.detail, fix: '', exploit: p.exploit || '', line: 0, kind: 'dynamic'
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

  let verdict;
  if (counts.Critical > 0) verdict = '🔴 بحرانی — یافته‌ای با اثر فاجعه‌بار وجود دارد؛ پیش از استقرار حتماً رفع و با حسابرس مستقل تأیید شود.';
  else if (counts.High > 0) verdict = '🟠 خطرناک — چند یافته مهم؛ سرمایه در خطر است و بررسی فوری لازم است.';
  else if (counts.Medium > 0) verdict = '🟡 ریسک متوسط — مواردی نیازمند بررسی دستی/تأیید حسابرس است.';
  else if (counts.Low > 0) verdict = '🟢 ریسک پایین — موارد جزئی؛ برای استقرار ارزشمند هنوز با حسابرس مستقل تأیید شود.';
  else verdict = '⚪ بدون یافته قابل توجه — همچنان با حسابرس مستقل تأیید شود.';

  all.sort((a, b) => (sevOrder[a.sev] - sevOrder[b.sev]));
  return { findings: all, counts, verdict, durationMs: dynamic.durationMs, contractCount: (abi || []).length };
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
  if (report.verdict) lines.push('**ارزیابی:** ' + report.verdict.replace(/^[^\s]*\s/, ''));
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
    if (f.exploit) {
      lines.push('');
      lines.push('**بهره‌برداری / PoC:** ' + f.exploit);
    }
    lines.push('');
  });
  return lines.join('\n');
}

// Shared wording for the contest report — used by the markdown generator and
// by the UI's live preview so both always stay in sync.
const CONTEST_TONES = {
  formal: {
    intro: (c, a) => (a
      ? a + ' با ترکیبی از تحلیل دستی، قوانین استاتیک و شبیه‌سازی حمله در EVM مرورگر قرارداد «' + c + '» را بررسی کرده است.'
      : 'این سند نتیجهٔ بررسی امنیتی قرارداد «' + c + '» است؛ بررسی با ترکیبی از تحلیل دستی، قوانین استاتیک و شبیه‌سازی حمله در EVM مرورگر انجام شده است.'),
    conclusionLabel: 'نتیجه‌گیری و توصیه‌های کلی',
    findingIntro: 'یافته‌ها به ترتیب شدت ارائه می‌شوند:'
  },
  concise: {
    intro: (c, a) => 'Audit — ' + c + (a ? ' | بررسی‌کننده: ' + a : '') + ' | روش: Manual + Heuristic Static + EVM Simulation.',
    conclusionLabel: 'جمع‌بندی',
    findingIntro: 'یافته‌ها به ترتیب شدت:'
  },
  narrative: {
    intro: (c, a) => (a || 'حسابرس') + ' کد قرارداد «' + c + '» را خط‌به‌خط بررسی کرد تا ببیند مهاجم از کجا می‌تواند وارد شود. آنچه پیدا شد در ادامه آمده است.',
    conclusionLabel: 'جمع‌بندی نهایی',
    findingIntro: 'مسیر ورود مهاجم، از خطرناک‌ترین شروع می‌شود:'
  }
};

export function contestTone(tone) {
  return CONTEST_TONES[tone] || CONTEST_TONES.formal;
}

// Contest-style report (Code4rena / Sherlock submission format). Each finding
// gets the standard sections: Summary, Vulnerability Details, Impact, PoC,
// Recommended Mitigation — ready to paste into the submission form.
//
// Personalization options (`opts`):
//   contractName     — contract label used in the title
//   auditorName      — handle / auditor name (fills the Handle section)
//   tone             — 'formal' | 'concise' | 'narrative' (intro wording)
//   customNote       — optional note placed right after the intro
//   signature        — optional footer block at the very end
//   includeConclusion— if false, the conclusion section is omitted (default true)
export function reportToContestMd(report, fileName, surface, opts) {
  const o = opts || {};
  const fname = o.contractName || fileName || 'Security.sol';
  const auditor = (o.auditorName || '').trim();
  const tone = o.tone || 'formal';
  const includeConclusion = o.includeConclusion !== false;
  const t = contestTone(tone);

  const lines = [];
  lines.push('# Security Report — ' + fname);
  lines.push('');
  lines.push(t.intro(fname, auditor));
  if ((o.customNote || '').trim()) {
    lines.push('');
    lines.push('> ' + o.customNote.trim().split('\n').join('\n> '));
  }
  lines.push('');
  lines.push('## Handle');
  lines.push('');
  if (auditor) lines.push(auditor);
  lines.push('## Risk Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push('| Critical | ' + report.counts.Critical + ' |');
  lines.push('| High | ' + report.counts.High + ' |');
  lines.push('| Medium | ' + report.counts.Medium + ' |');
  lines.push('| Low | ' + report.counts.Low + ' |');
  lines.push('| Info | ' + report.counts.Info + ' |');
  lines.push('');
  if (surface && surface.contracts && surface.contracts.length) {
    lines.push('## Attack Surface');
    lines.push('');
    if (surface.roles && surface.roles.length) {
      lines.push('**Roles:** ' + surface.roles.map(r => r.name + ' (' + r.from + ')').join('; '));
      lines.push('');
    }
    if (surface.assets && surface.assets.length) {
      lines.push('**Assets at risk:** ' + surface.assets.map(a => a.name + ' — ' + a.desc).join('; '));
      lines.push('');
    }
    surface.contracts.forEach(c => {
      lines.push('### ' + c.name + ' (' + c.contractKind + ')');
      if (c.stateVars && c.stateVars.length) lines.push('- State: ' + c.stateVars.join(', '));
      if (c.entrypoints && c.entrypoints.length) {
        lines.push('- Entrypoints:');
        c.entrypoints.forEach(e => {
          lines.push('  - `' + e.name + '(' + (e.args || []).join(', ') + ')` [' + (e.stateMutability || 'nonpayable') + ']' + (e.mods.length ? ' — mods: ' + e.mods.join(', ') : '') + (e.guard ? ' — guard: `' + e.guard + '`' : ''));
        });
      }
      lines.push('');
    });
  }
  lines.push('## Findings');
  lines.push('');
  lines.push(t.findingIntro);
  lines.push('');
  report.findings.forEach((f, i) => {
    const tag = '[' + f.sev + '-' + (i + 1) + ']';
    lines.push('### ' + tag + ' ' + f.title);
    lines.push('');
    lines.push('**Lines:** ' + fname + (f.line ? ':' + f.line : ''));
    lines.push('');
    lines.push('**Summary:** ' + f.detail);
    lines.push('');
    lines.push('**Vulnerability Details:** ' + f.detail + (f.kind === 'dynamic' ? ' (تأیید شده با شبیه‌سازی حمله در EVM مرورگر)' : ''));
    lines.push('');
    lines.push('**Impact:** ' + (f.sev === 'Critical' || f.sev === 'High'
      ? 'منجر به از دست رفتن وجوه / ربایش کنترل قرارداد / خسارت اقتصادی قابل‌توجه می‌شود.'
      : (f.sev === 'Medium' ? 'اثر اقتصادی محدود یا وابسته به شرایط؛ نیازمند تأیید دستی.' : 'یافته اطلاعاتی/جزئی؛ بدون اثر اقتصادی مستقیم.')));
    if (f.exploit) {
      lines.push('');
      lines.push('**Proof of Concept:** ' + f.exploit);
    }
    if (f.fix) {
      lines.push('');
      lines.push('**Recommended Mitigation:** ' + f.fix);
    }
    lines.push('');
  });
  if (includeConclusion) {
    lines.push('## ' + t.conclusionLabel);
    lines.push('');
    lines.push('[ریسک کلی قرارداد، نکات باقی‌مانده و اولویت رفع را اینجا بنویس.]');
    lines.push('');
  }
  lines.push('## Tools Used');
  lines.push('');
  lines.push('- Security Lab: static rules + AST expert analyzer + browser-EVM dynamic exploit probes (https://rahmatpourmba-crypto.github.io/smart-contract-editor/)');
  if ((o.signature || '').trim()) {
    lines.push('');
    lines.push(o.signature.trim());
  }
  return lines.join('\n');
}

// Draft Foundry test that the auditor can complete. Uses forge-std/Test,
// pranks the attacker/owner and opens a TODO stub per High/Critical finding,
// plus a reentrancy attack contract when a CEI/reentrancy finding exists.
export function foundryPoC(report, fileName) {
  const fname = (fileName || 'Security.sol').replace(/\.sol$/i, '') || 'Security';
  const l = [];
  l.push('// Foundry PoC draft — generated by Security Lab');
  l.push('// Place this file under test/, the target under src/, then run: forge test -vvv');
  l.push('// SPDX-License-Identifier: UNLICENSED');
  l.push('pragma solidity ^0.8.19;');
  l.push('');
  l.push('import {Test} from "forge-std/Test.sol";');
  l.push('import {' + fname + '} from "../src/' + fname + '.sol";');
  l.push('');
  l.push('// NOTE: rename `' + fname + '` in the import to the real contract name if it differs.');
  l.push('contract ' + fname + 'Attack is Test {');
  l.push('    ' + fname + ' target;');
  l.push('    address attacker = 0x2222222222222222222222222222222222222222;');
  l.push('    address owner = 0x1111111111111111111111111111111111111111;');
  l.push('');
  l.push('    function setUp() public {');
  l.push('        vm.prank(owner);');
  l.push('        target = new ' + fname + '();');
  l.push('        vm.deal(attacker, 1 ether);');
  l.push('    }');
  l.push('');
  const targets = report.findings.filter(f => f.sev === 'Critical' || f.sev === 'High');
  targets.forEach((f, i) => {
    l.push('    // [' + f.sev + '-' + (i + 1) + '] ' + f.title);
    l.push('    // ' + f.detail.replace(/\n/g, ' '));
    if (f.exploit) l.push('    // PoC hint: ' + f.exploit.replace(/\n/g, ' '));
    l.push('    function testPoC_' + (i + 1) + '() public {');
    l.push('        vm.startPrank(attacker);');
    l.push('        // TODO: complete the attack sequence with real values.');
    l.push('        // target.<function>(...);');
    l.push('        vm.stopPrank();');
    l.push('        // vm.assertEq(target.<stateGetter>(), <expected>, "pwned");');
    l.push('    }');
    l.push('');
  });
  if (!targets.length) {
    l.push('    // No High/Critical finding — nothing to exploit in this draft.');
    l.push('');
  }
  l.push('}');
  const reent = report.findings.find(f => /reentrancy|Reentrancy|ورود مجدد|شکستن CEI|CEI/i.test((f.title || '') + ' ' + (f.detail || '')));
  if (reent) {
    l.push('');
    l.push('contract ReentrancyAttacker {');
    l.push('    ' + fname + ' target;');
    l.push('    bool private entered;');
    l.push('');
    l.push('    constructor(' + fname + ' _target) { target = _target; }');
    l.push('');
    l.push('    function attack() external payable {');
    l.push('        // target.<vulnerableFunction>(...); // first entry');
    l.push('    }');
    l.push('');
    l.push('    receive() external payable {');
    l.push('        if (!entered) {');
    l.push('            entered = true;');
    l.push('            // target.<vulnerableFunction>(...); // re-enter before state updates');
    l.push('        }');
    l.push('    }');
    l.push('}');
  }
  return l.join('\n');
}
