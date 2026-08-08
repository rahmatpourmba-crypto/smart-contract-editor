/* In-browser runtime test engine using @ethereumjs/vm (esm.sh bundle).
 * Runs the compiled bytecode in a local EVM and checks ERC-20 behaviour.
 * No network, no wallet, no gas required.
 */
import { VM } from '@ethereumjs/vm';
import { Address } from '@ethereumjs/util';
import { Common } from '@ethereumjs/common';
import { keccak_256 } from '@noble/hashes/sha3';
import { Buffer } from 'node:buffer';

const MAXUINT = (1n << 256n) - 1n;
const S = 10n ** 18n;

const OWNER = '0x1111111111111111111111111111111111111111';
const U2 = '0x2222222222222222222222222222222222222222';
const U3 = '0x3333333333333333333333333333333333333333';
const U4 = '0x4444444444444444444444444444444444444444';
const U5 = '0x5555555555555555555555555555555555555555';
const U6 = '0x6666666666666666666666666666666666666666';

function hexWord(v) { return v.toString(16).padStart(64, '0'); }
function padAddr(addr) { return '000000000000000000000000' + addr.slice(2).toLowerCase(); }

function sigOf(frag) {
  return frag.name + '(' + frag.inputs.map(i => i.type).join(',') + ')';
}

function encodeArgs(frag, values) {
  let head = '';
  let tail = '';
  frag.inputs.forEach((inp, i) => {
    const t = inp.type;
    const v = values[i];
    if (t === 'address') { head += padAddr(v); }
    else if (t === 'bool') { head += hexWord(v ? 1n : 0n); }
    else if (/^uint(\d+)?$/.test(t)) { head += hexWord(BigInt(v)); }
    else if (t === 'string') {
      const bytes = Buffer.from(String(v), 'utf8');
      const len = bytes.length;
      head += hexWord(BigInt(head.length / 2));
      tail += hexWord(BigInt(len)) + bytes.toString('hex').padEnd(64, '0');
    } else {
      throw new Error('Unsupported type: ' + t);
    }
  });
  return Buffer.from((head + tail), 'hex');
}

function encodeCall(frag, values) {
  const sel = keccak_256(new TextEncoder().encode(sigOf(frag))).subarray(0, 4);
  return Buffer.concat([Buffer.from(sel), encodeArgs(frag, values)]);
}

function decodeReturn(frag, rv) {
  const hex = Array.from(rv).map(b => b.toString(16).padStart(2, '0')).join('');
  const out = frag.outputs && frag.outputs[0];
  if (!out) return null;
  const t = out.type;
  if (t === 'bool') return hex.slice(0, 64) !== '0'.repeat(64);
  if (/^uint(\d+)?$/.test(t)) return BigInt('0x' + hex.slice(0, 64));
  if (t === 'address') return '0x' + hex.slice(24, 64);
  if (t === 'string') {
    const off = parseInt(hex.slice(0, 64), 16) * 2;
    const len = parseInt(hex.slice(off, off + 64), 16) * 2;
    return Buffer.from(hex.slice(off + 64, off + 64 + len), 'hex').toString('utf8');
  }
  return null;
}

export async function runContractTests(abi, bytecode, expect) {
  const started = Date.now();
  const results = [];
  const record = (label, ok, detail) => results.push({ label, ok, detail });

  const has = (name) => abi.some(f => f.type === 'function' && f.name === name);
  const frag = (name) => abi.find(f => f.type === 'function' && f.name === name);

  // solc 0.8.25+ targets Cancun and emits MCOPY for string getters, which is
  // not available on the default (shanghai) hardfork.
  const common = Common.custom({ chainId: 1 }, { hardfork: 'cancun' });
  const vm = await VM.create({ common });
  const ownerAddr = Address.fromString(OWNER);
  let contractAddr = null;

  async function exec(from, to, data) {
    const res = await vm.evm.runCall({
      caller: Address.fromString(from),
      to: to || undefined,
      data,
      gasLimit: 0xFFFFFFFFn,
      gasPrice: 1n,
      value: 0n
    });
    const err = (res.execResult && res.execResult.exceptionError) || res.exceptionError;
    return { reverted: !!err, error: err ? (err.error || err) : null, res, created: res.createdAddress || (res.execResult && res.execResult.createdAddress) };
  }

  async function view(fname, from, args) {
    const f = frag(fname);
    const r = await exec(from || OWNER, contractAddr, encodeCall(f, args || []));
    if (r.reverted) throw new Error(fname + ' reverted: ' + r.error);
    return decodeReturn(f, r.res.execResult.returnValue);
  }

  async function txn(fname, from, args) {
    const f = frag(fname);
    return exec(from || OWNER, contractAddr, encodeCall(f, args || []));
  }

  const c = { abi, has, frag, exec, view, txn, expect };

  // ---------- 1. Deploy ----------
  const create = await exec(OWNER, null, Buffer.from(bytecode.slice(2), 'hex'));
  const deployed = create.created;
  record('استقرار قرارداد (deploy)', !!deployed && !create.reverted, deployed ? deployed.toString() : (create.error || ''));
  if (deployed) contractAddr = Address.fromString(deployed.toString());
  if (!deployed) {
    return { results, passed: 0, total: 1, durationMs: Date.now() - started };
  }

  // ---------- 2. Metadata ----------
  try {
    const name = has('name') ? await view('name') : '';
    const symbol = has('symbol') ? await view('symbol') : '';
    const nameOk = expect && expect.name ? name === expect.name : name.length > 0;
    const symOk = expect && expect.symbol ? symbol === expect.symbol : symbol.length > 0;
    record('نام و نماد توکن', nameOk && symOk, `name=${name} symbol=${symbol}`);
  } catch (e) { record('نام و نماد توکن', false, e.message); }

  // ---------- 3. Supply minted to owner ----------
  try {
    const supply = has('totalSupply') ? await view('totalSupply') : 0n;
    const ownerBal = has('balanceOf') ? await view('balanceOf', OWNER, [OWNER]) : 0n;
    let ok = ownerBal === supply;
    let detail = `totalSupply=${supply / S} ownerBal=${ownerBal / S}`;
    if (expect && expect.supply !== undefined) {
      const want = BigInt(expect.supply) * S;
      ok = ok && supply === want;
      detail += ` (expected ${want / S})`;
    }
    record('عرضه اولیه در اختیار مالک', ok, detail);
  } catch (e) { record('عرضه اولیه در اختیار مالک', false, e.message); }

  // whitelist u2/u3 upfront so later tests work regardless of whitelistEnabled
  if (has('setWhitelisted')) {
    await txn('setWhitelisted', OWNER, [U2, true]).catch(() => {});
    await txn('setWhitelisted', OWNER, [U3, true]).catch(() => {});
  }

  // ---------- 4. Basic transfer (owner is tax-exempt) ----------
  try {
    const amt = 100n * S;
    const b0 = has('balanceOf') ? await view('balanceOf', OWNER, [OWNER]) : 0n;
    const r = await txn('transfer', OWNER, [U2, amt]);
    const b1 = has('balanceOf') ? await view('balanceOf', OWNER, [OWNER]) : 0n;
    const b2 = has('balanceOf') ? await view('balanceOf', U2, [U2]) : 0n;
    record('انتقال پایه (مالک → کاربر)', !r.reverted && b1 === b0 - amt && b2 === amt, `owner-${(b0 - b1) / S} user+${b2 / S}`);
  } catch (e) { record('انتقال پایه (مالک → کاربر)', false, e.message); }

  // ---------- 5. approve + transferFrom ----------
  if (has('approve') && has('transferFrom')) {
    try {
      const amt = 40n * S;
      await txn('approve', U2, [U3, amt]);
      const u3Before = has('balanceOf') ? await view('balanceOf', U3, [U3]) : 0n;
      const r = await txn('transferFrom', U3, [U2, U3, amt]);
      const u3After = has('balanceOf') ? await view('balanceOf', U3, [U3]) : 0n;
      const allowance = has('allowance') ? await view('allowance', U3, [U2, U3]) : 0n;
      record('approve + transferFrom', !r.reverted && u3After > u3Before && allowance === 0n, `u3+${(u3After - u3Before) / S}`);
    } catch (e) { record('approve + transferFrom', false, e.message); }
  }

  // ---------- 6. Tax on regular transfer (premium) ----------
  if (has('transferTax') && has('burnShare') && has('marketingWallet')) {
    try {
      const taxBp = await view('transferTax');
      const burnPct = await view('burnShare');
      const mkt = await view('marketingWallet');
      const amt = 100n * S;
      await txn('transfer', OWNER, [U2, 100n * S]);
      const mkt0 = await view('balanceOf', OWNER, [mkt]);
      const u30 = await view('balanceOf', U3, [U3]);
      const r = await txn('transfer', U2, [U3, amt]);
      const mkt1 = await view('balanceOf', OWNER, [mkt]);
      const u31 = await view('balanceOf', U3, [U3]);
      const taxAmount = (amt * taxBp) / 10000n;
      const burnPart = (taxAmount * burnPct) / 100n;
      const feeToWallet = taxAmount - burnPart;
      const amountOut = amt - taxAmount;
      const ok = !r.reverted && (u31 - u30) === amountOut && (mkt1 - mkt0) === feeToWallet;
      record('مالیات روی انتقال عادی', ok, `tax=${taxBp / 100n}% burn=${burnPct}% out=${(u31 - u30) / S} fee=${(mkt1 - mkt0) / S}`);
    } catch (e) { record('مالیات روی انتقال عادی', false, e.message); }
  }

  // ---------- 7. Whitelist ----------
  if (has('whitelistEnabled')) {
    try {
      if (await view('whitelistEnabled')) await txn('setWhitelistEnabled', OWNER, [false]);
      await txn('transfer', OWNER, [U4, 100n * S]); // fund outsiders while off
      await txn('transfer', OWNER, [U5, 100n * S]);
      await txn('transfer', OWNER, [U2, 100n * S]);
      await txn('transfer', OWNER, [U3, 100n * S]);
      await txn('setWhitelistEnabled', OWNER, [true]);
      const r1 = await txn('transfer', U4, [U2, 10n * S]);
      const r2 = await txn('transfer', U2, [U4, 10n * S]);
      const r3 = await txn('transfer', U2, [U3, 10n * S]);
      await txn('setWhitelistEnabled', OWNER, [false]);
      const ok = r1.reverted && r2.reverted && !r3.reverted;
      record('وایتلیست (فقط آدرسهای مجاز)', ok, r1.reverted && r2.reverted && !r3.reverted ? 'غیرمجاز رد شد، مجاز عبور کرد' : `r1=${r1.reverted} r2=${r2.reverted} r3=${r3.reverted}`);
    } catch (e) { record('وایتلیست (فقط آدرسهای مجاز)', false, e.message); }
  }

  // ---------- 8. Pause ----------
  if (has('paused')) {
    try {
      await txn('transfer', OWNER, [U2, 100n * S]);
      await txn('setPaused', OWNER, [true]);
      const r1 = await txn('transfer', U2, [U3, 10n * S]);
      await txn('setPaused', OWNER, [false]);
      const r2 = await txn('transfer', U2, [U3, 10n * S]);
      record('توقف اضطراری (Pausable)', r1.reverted && !r2.reverted, 'متوقف شد و دوباره فعال شد');
    } catch (e) { record('توقف اضطراری (Pausable)', false, e.message); }
  }

  // ---------- 9. Blacklist ----------
  if (has('isBlacklisted')) {
    try {
      await txn('transfer', OWNER, [U2, 100n * S]);
      await txn('setBlacklisted', OWNER, [U3, true]);
      const r1 = await txn('transfer', U2, [U3, 10n * S]);
      await txn('setBlacklisted', OWNER, [U3, false]);
      const r2 = await txn('transfer', U2, [U3, 10n * S]);
      record('بلاکلیست', r1.reverted && !r2.reverted, 'مسدود شد و آزاد شد');
    } catch (e) { record('بلاکلیست', false, e.message); }
  }

  // ---------- 10. Max-tx ----------
  if (has('maxTxAmount')) {
    try {
      const cap = await view('maxTxAmount');
      if (cap < MAXUINT) {
        const r1 = await txn('transfer', OWNER, [U2, cap + 1n]);
        const r2 = await txn('transfer', OWNER, [U2, 100n * S]);
        record('سقف هر تراکنش (MaxTx)', r1.reverted && !r2.reverted, `cap=${cap / S} ٪عرضه، بیش از سقف رد شد`);
      } else {
        record('سقف هر تراکنش (MaxTx)', true, 'غیرفعال');
      }
    } catch (e) { record('سقف هر تراکنش (MaxTx)', false, e.message); }
  }

  // ---------- 11. Anti-whale ----------
  if (has('maxWalletAmount')) {
    try {
      const cap = await view('maxWalletAmount');
      if (cap < MAXUINT) {
        const r1 = await txn('transfer', OWNER, [U6, cap + 1n]);
        const r2 = await txn('transfer', OWNER, [U6, cap]);
        record('ضد نهنگ (سقف نگهداری)', r1.reverted && !r2.reverted, `cap=${cap / S}، بیش از سقف رد شد`);
      } else {
        record('ضد نهنگ (سقف نگهداری)', true, 'غیرفعال');
      }
    } catch (e) { record('ضد نهنگ (سقف نگهداری)', false, e.message); }
  }

  // ---------- 12. Burn ----------
  if (has('burn')) {
    try {
      const amt = 10n * S;
      const sup0 = await view('totalSupply');
      const bal0 = await view('balanceOf', OWNER, [OWNER]);
      const r = await txn('burn', OWNER, [amt]);
      const sup1 = await view('totalSupply');
      const bal1 = await view('balanceOf', OWNER, [OWNER]);
      record('سوزاندن (Burn)', !r.reverted && sup0 - sup1 === amt && bal0 - bal1 === amt, `supply-${(sup0 - sup1) / S}`);
    } catch (e) { record('سوزاندن (Burn)', false, e.message); }
  }

  // ---------- 13. Lock ----------
  if (has('lock') && has('forceUnlock')) {
    try {
      await txn('lock', OWNER, [U2, 1000000n]);
      const r1 = await txn('transfer', U2, [U3, 10n * S]);
      await txn('forceUnlock', OWNER, [U2]);
      const r2 = await txn('transfer', U2, [U3, 10n * S]);
      record('قفل سرمایهگذار (Lock)', r1.reverted && !r2.reverted, 'قفل شد و آزاد شد');
    } catch (e) { record('قفل سرمایهگذار (Lock)', false, e.message); }
  }

  const passed = results.filter(r => r.ok).length;
  const total = results.length;
  return { results, passed, total, durationMs: Date.now() - started };
}
