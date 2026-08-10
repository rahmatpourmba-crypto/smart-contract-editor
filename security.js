'use strict';

/* Security Lab UI: paste any contract or pull the current editor / token
 * generator source, run static + dynamic (browser EVM) security checks and
 * render a severity-tagged report. */
(function () {
  const panel = document.getElementById('panel-security');
  if (!panel) return;

  const source = document.getElementById('sec-source');
  const btnUseEditor = document.getElementById('sec-use-editor');
  const btnUseToken = document.getElementById('sec-use-token');
  const btnRun = document.getElementById('sec-run');
  const btnCopy = document.getElementById('sec-copy');
  const btnDl = document.getElementById('sec-dl');
  const btnContest = document.getElementById('sec-contest');
  const btnPoc = document.getElementById('sec-poc');
  const loading = document.getElementById('sec-loading');
  const report = document.getElementById('sec-report');
  const reportPanel = document.getElementById('sec-report-panel');
  const reportPreview = document.getElementById('sec-report-preview');
  const reportRaw = document.getElementById('sec-report-raw');
  const inpCName = document.getElementById('sec-cname');
  const inpAuditor = document.getElementById('sec-auditor');
  const inpTone = document.getElementById('sec-tone');
  const inpNote = document.getElementById('sec-note');
  const inpSign = document.getElementById('sec-sign');
  const inpConclusion = document.getElementById('sec-conclusion');

  let lastContestMd = '';
  let lastPoC = '';
  let lastGenerated = null;

  function download(name, text, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 400);
  }

  const SEV = {
    Critical: { cls: 'sev-critical', label: 'بحرانی' },
    High: { cls: 'sev-high', label: 'بالا' },
    Medium: { cls: 'sev-medium', label: 'متوسط' },
    Low: { cls: 'sev-low', label: 'پایین' },
    Info: { cls: 'sev-info', label: 'اطلاعاتی' }
  };

  function setLoading(msg) {
    loading.textContent = msg || '';
  }

  function personalizationOpts(fileLabel) {
    return {
      contractName: (inpCName.value || '').trim() || fileLabel,
      auditorName: (inpAuditor.value || '').trim(),
      tone: inpTone.value || 'formal',
      customNote: inpNote.value,
      signature: inpSign.value,
      includeConclusion: inpConclusion.checked
    };
  }

  btnUseEditor.addEventListener('click', () => {
    if (editor && editor.getValue()) {
      source.value = editor.getValue();
      setLoading('سورس از ادیتور بارگذاری شد.');
    }
  });

  btnUseToken.addEventListener('click', () => {
    try {
      const opts = readOpts();
      if (!opts) { setLoading('فرم توکن ساز را کامل کن.'); return; }
      const res = buildToken(opts);
      lastGenerated = res;
      source.value = res.src;
      setLoading('سورس از توکن ساز بارگذاری شد: ' + res.fileName);
    } catch (e) {
      setLoading('خطا در ساخت توکن: ' + e.message);
    }
  });

  async function run() {
    const src = source.value.trim();
    if (!src) { setLoading('اول سورس Solidity را وارد کن.'); return; }
    if (!solcReady) { setLoading('کامپایلر هنوز بارگذاری نشده. کمی صبر کن.'); return; }

    btnRun.disabled = true;
    report.innerHTML = '';
    reportPanel.classList.add('hidden');
    setLoading('⏳ در حال تحلیل امنیتی (کامپایل + AST + اسکن استاتیک + اکسپلویت در EVM مرورگر)...');

    const statics = [];
    try {
      const mod = await import('./security-test.js');
      const fileLabel = lastGenerated && lastGenerated.fileName ? lastGenerated.fileName : 'Security.sol';
      const input = {
        language: 'Solidity',
        sources: {},
        settings: {
          optimizer: { enabled: document.getElementById('chk-optimize').checked, runs: 200 },
          outputSelection: { '*': { '': ['ast'], '*': ['abi', 'evm.bytecode'] } }
        }
      };
      input.sources[fileLabel] = { content: src };

      let abi = null;
      let bytecode = null;
      let ast = null;
      let compileErrors = null;
      try {
        const out = JSON.parse(await solc.compile(JSON.stringify(input)));
        compileErrors = (out.errors || []).filter(e => e.severity === 'error');
        const contracts = out.contracts && out.contracts[fileLabel];
        const cname = contracts ? Object.keys(contracts)[0] : null;
        const c = cname && contracts[cname];
        if (c && c.abi && c.evm && c.evm.bytecode && c.evm.bytecode.object) {
          abi = c.abi;
          bytecode = '0x' + c.evm.bytecode.object;
        }
        ast = (out.sources && out.sources[fileLabel] && out.sources[fileLabel].ast) || null;
      } catch (e) {
        compileErrors = [{ formattedMessage: e.message }];
      }

      const astRes = ast ? mod.astAnalyze(ast, src) : { findings: [], contracts: [] };
      const surface = ast ? mod.attackSurface(ast, src) : null;
      const staticFindings = mod.staticScan(src).concat(astRes.findings);
      let dynamic = null;
      if (abi && bytecode) {
        dynamic = await mod.runSecurityTests(abi, bytecode, src);
      } else {
        dynamic = { probes: [], durationMs: 0 };
      }

      const compiled = mod.buildReport(src, abi, bytecode, staticFindings, dynamic);
      if (compileErrors && compileErrors.length) {
        compiled.compileError = compileErrors[0].formattedMessage;
      }
      const opts = personalizationOpts(fileLabel);
      render(compiled, mod, surface);
      lastContestMd = mod.reportToContestMd(compiled, fileLabel, surface, opts);
      lastPoC = mod.foundryPoC(compiled, fileLabel);
      renderReport(compiled, surface, opts, mod);
      btnContest.classList.remove('hidden');
      btnPoc.classList.remove('hidden');
      setLoading('');
    } catch (e) {
      setLoading('❌ خطا: ' + e.message);
    } finally {
      btnRun.disabled = false;
    }
  }

  function render(rep, mod, surface) {
    const html = [];
    const h = (s) => { html.push(s); };

    if (surface && surface.contracts && surface.contracts.length) {
      h('<details class="sec-surface">');
      h('<summary>🎯 سطح حمله (Attack Surface) — ' + surface.contracts.length + ' قرارداد</summary>');
      if (surface.roles && surface.roles.length) {
        h('<div class="sec-surface-row"><span class="sec-surface-tag">نقش‌ها:</span> ' +
          surface.roles.map(r => '<code>' + escapeHtml(r.name) + '</code> <span class="muted">(' + escapeHtml(r.from) + ')</span>').join('، ') + '</div>');
      }
      if (surface.assets && surface.assets.length) {
        h('<div class="sec-surface-row"><span class="sec-surface-tag">دارایی‌های در خطر:</span> ' +
          surface.assets.map(a => '<code>' + escapeHtml(a.name) + '</code> <span class="muted">(' + escapeHtml(a.desc) + ')</span>').join('، ') + '</div>');
      }
      surface.contracts.forEach(c => {
        h('<div class="sec-surface-contract">');
        h('<b>' + escapeHtml(c.name) + '</b> <span class="muted">(' + escapeHtml(c.contractKind) + ')</span>');
        if (c.stateVars && c.stateVars.length) h('<div class="sec-surface-row"><span class="sec-surface-tag">state:</span> <code>' + escapeHtml(c.stateVars.join(', ')) + '</code></div>');
        if (c.entrypoints && c.entrypoints.length) {
          h('<div class="sec-surface-row"><span class="sec-surface-tag">ورودی‌های عمومی:</span></div>');
          h('<ul class="sec-surface-eps">');
          c.entrypoints.forEach(e => {
            const line = '<code>' + escapeHtml(e.name + '(' + (e.args || []).join(', ') + ')') + '</code> <span class="muted">[' + escapeHtml(e.stateMutability || 'nonpayable') + ']</span>' +
              (e.mods.length ? ' <span class="muted">mods: ' + escapeHtml(e.mods.join(', ')) + '</span>' : '') +
              (e.guard ? ' <span class="muted">guard: <code>' + escapeHtml(e.guard) + '</code></span>' : '');
            h('<li>' + line + '</li>');
          });
          h('</ul>');
        }
        h('</div>');
      });
      h('</details>');
    }

    h('<div class="sec-summary">');
    h('<span class="sec-sum-title">گزارش امنیتی</span>');
    h('<span class="sec-counts">');
    ['Critical', 'High', 'Medium', 'Low', 'Info'].forEach(sev => {
      if (rep.counts[sev] > 0) {
        h('<span class="sev-badge ' + SEV[sev].cls + '">' + SEV[sev].label + ' ' + rep.counts[sev] + '</span>');
      }
    });
    h('<span class="sec-dur">' + rep.durationMs + 'ms</span>');
    h('</span>');
    h('</div>');
    if (rep.verdict) h('<div class="sec-verdict">' + escapeHtml(rep.verdict) + '</div>');

    if (rep.compileError) {
      h('<div class="sec-compile-err">⚠ کامپایل ناقص بود — فقط تحلیل استاتیک نمایش داده می‌شود.<br><code>' + escapeHtml(rep.compileError) + '</code></div>');
    }

    if (!rep.findings.length) {
      h('<div class="sec-clean">✅ هیچ یافته‌ای پیدا نشد. (این جایگزین حسابرسی حرفه‌ای نیست.)</div>');
    }

    const groups = {};
    rep.findings.forEach(f => { (groups[f.sev] = groups[f.sev] || []).push(f); });

    ['Critical', 'High', 'Medium', 'Low', 'Info'].forEach(sev => {
      (groups[sev] || []).forEach((f, i) => {
        const isDyn = f.kind === 'dynamic';
        const isAst = f.kind === 'ast';
        h('<div class="sec-finding ' + SEV[sev].cls + '">');
        h('<div class="sec-f-head">');
        h('<span class="sev-badge ' + SEV[sev].cls + '">' + SEV[sev].label + '</span>');
        h('<span class="sec-f-title">' + (isDyn ? '🧪 ' : isAst ? '📐 ' : '📄 ') + escapeHtml(f.title) + '</span>');
        h('<span class="sec-f-kind">' + (isDyn ? 'پویا (EVM)' : isAst ? 'تحلیلگر AST' + (f.line ? ' — خط ' + f.line : '') : 'استاتیک' + (f.line ? ' — خط ' + f.line : '')) + '</span>');
        h('</div>');
        h('<div class="sec-f-detail">' + escapeHtml(f.detail) + '</div>');
        if (f.exploit) h('<div class="sec-f-exploit">🚨 بهره‌برداری / PoC: ' + escapeHtml(f.exploit) + '</div>');
        if (f.fix) h('<div class="sec-f-fix">🛠 راه‌حل: ' + escapeHtml(f.fix) + '</div>');
        h('</div>');
      });
    });

    h('<div class="sec-disclaimer">این تحلیل خودکار به کمک قوانین استاتیک و شبیه‌سازی حمله در EVM مرورگر انجام شده و جایگزین حسابرسی انسانی حرفه‌ای نیست. نتایج را برای معامله‌های مهم با یک حسابرس مستقل تأیید کنید.</div>');

    report.innerHTML = html.join('');
  }

  function renderReport(rep, surface, opts, mod) {
    const fname = opts.contractName || 'Security.sol';
    const auditor = opts.auditorName || '';
    const date = new Date().toLocaleDateString('fa-IR');
    const t = mod && mod.contestTone ? mod.contestTone(opts.tone) : null;

    const sevMeta = {
      Critical: { label: 'بحرانی', cls: 'sev-critical', color: '#f38ba8' },
      High: { label: 'بالا', cls: 'sev-high', color: '#f9a35a' },
      Medium: { label: 'متوسط', cls: 'sev-medium', color: '#f9e2af' },
      Low: { label: 'پایین', cls: 'sev-low', color: '#89dceb' },
      Info: { label: 'اطلاعاتی', cls: 'sev-info', color: '#b4befe' }
    };
    const order = ['Critical', 'High', 'Medium', 'Low', 'Info'];

    const h = [];
    h.push('<h1 class="sr-title">گزارش امنیتی — ' + escapeHtml(fname) + '</h1>');
    h.push('<div class="sr-meta"><b>آدیتور:</b> ' + escapeHtml(auditor || '[نام خود را وارد کنید]') + '</div>');
    h.push('<div class="sr-meta"><b>قرارداد:</b> ' + escapeHtml(fname) + '</div>');
    h.push('<div class="sr-meta"><b>تاریخ:</b> ' + escapeHtml(date) + '</div>');
    h.push('<div class="sr-meta"><b>نوع بررسی:</b> Manual + Heuristic Static + EVM Simulation</div>');

    let intro = t ? t.intro(fname, auditor) : '';
    if (!intro) {
      intro = auditor
        ? auditor + ' با ترکیبی از تحلیل دستی و قوانین استاتیک قرارداد «' + fname + '» را بررسی کرده است.'
        : 'این سند نتیجهٔ بررسی امنیتی قرارداد «' + fname + '» است.';
    }
    h.push('<p class="sr-para">' + escapeHtml(intro) + '</p>');
    if ((opts.customNote || '').trim()) {
      h.push('<div class="sr-quote">' + escapeHtml(opts.customNote.trim()) + '</div>');
    }

    h.push('<hr class="sr-hr" />');
    h.push('<h2 class="sr-h2">خلاصهٔ یافته‌ها</h2>');
    h.push('<table class="sr-table">');
    h.push('<thead><tr><th class="sr-th">شدت</th><th class="sr-th">تعداد</th></tr></thead>');
    h.push('<tbody>');
    order.forEach(s => {
      h.push('<tr><td class="sr-td"><span class="sr-dot" style="background:' + sevMeta[s].color + '"></span>' + sevMeta[s].label + ' <span class="sr-td-dim">(' + s + ')</span></td><td class="sr-td">' + rep.counts[s] + '</td></tr>');
    });
    h.push('</tbody></table>');

    h.push('<hr class="sr-hr" />');
    h.push('<h2 class="sr-h2">یافته‌ها</h2>');
    if (t) h.push('<p class="sr-para">' + escapeHtml(t.findingIntro) + '</p>');
    if (!rep.findings.length) {
      h.push('<p class="sr-para">هیچ الگوی مشکوکی توسط چک‌لیست شناسایی نشد.</p>');
    }
    rep.findings.forEach((f, i) => {
      const m = sevMeta[f.sev] || sevMeta.Info;
      h.push('<div class="sr-finding">');
      h.push('<h3 class="sr-h3">[' + escapeHtml(f.sev) + '-' + (i + 1) + '] ' + escapeHtml(f.title) + '</h3>');
      h.push('<div class="sr-meta"><span class="sr-sev-tag" style="background:' + m.color + '">' + m.label + '</span> <b>دسته‌بندی:</b> ' + escapeHtml(f.category || (f.kind === 'dynamic' ? 'Dynamic' : 'Static')) + ' <span class="sr-td-dim">(' + escapeHtml(f.kind === 'dynamic' ? 'پویا EVM' : f.kind === 'ast' ? 'AST' : 'استاتیک') + ')</span></div>');
      if (f.line) h.push('<div class="sr-meta"><b>خط:</b> ' + escapeHtml(fname) + ':' + f.line + '</div>');
      h.push('<div class="sr-detail">' + escapeHtml(f.detail) + '</div>');
      if (f.exploit) h.push('<div class="sr-exploit">🚨 بهره‌برداری / PoC: ' + escapeHtml(f.exploit) + '</div>');
      if (f.fix) h.push('<div class="sr-fix">🛠 راه‌حل: ' + escapeHtml(f.fix) + '</div>');
      h.push('</div>');
    });

    if (opts.includeConclusion !== false) {
      h.push('<hr class="sr-hr" />');
      h.push('<h2 class="sr-h2">' + escapeHtml(t ? t.conclusionLabel : 'نتیجه‌گیری و توصیه‌های کلی') + '</h2>');
      h.push('<div class="sr-placeholder">[ریسک کلی قرارداد، نکات باقی‌مانده و اولویت رفع را اینجا بنویس.]</div>');
    }
    if ((opts.signature || '').trim()) {
      h.push('<hr class="sr-hr" />');
      h.push('<div class="sr-sig">' + escapeHtml(opts.signature.trim()) + '</div>');
    }

    reportPreview.innerHTML = h.join('');
    reportRaw.textContent = lastContestMd;
    reportPanel.classList.remove('hidden');
  }

  document.querySelectorAll('.sec-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const view = tab.dataset.view;
      document.querySelectorAll('.sec-tab').forEach(x => x.classList.toggle('active', x === tab));
      reportPreview.classList.toggle('hidden', view !== 'preview');
      reportRaw.classList.toggle('hidden', view !== 'markdown');
    });
  });

  btnCopy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(lastContestMd);
      setLoading('گزارش مسابقه کپی شد (شامل شخصی‌سازی).');
    } catch (e) {
      setLoading('کپی ناموفق: ' + e.message);
    }
  });

  btnDl.addEventListener('click', () => {
    if (!lastContestMd) { setLoading('اول یک تحلیل امنیتی اجرا کن.'); return; }
    download('security-report-contest.md', lastContestMd, 'text/markdown;charset=utf-8');
    setLoading('گزارش مسابقه (شخصی‌سازی‌شده) دانلود شد.');
  });

  btnContest.addEventListener('click', () => {
    if (!lastContestMd) { setLoading('اول یک تحلیل امنیتی اجرا کن.'); return; }
    download('security-report-contest.md', lastContestMd, 'text/markdown;charset=utf-8');
    setLoading('گزارش مسابقه (C4/Sherlock) دانلود شد.');
  });

  btnPoc.addEventListener('click', () => {
    if (!lastPoC) { setLoading('اول یک تحلیل امنیتی اجرا کن.'); return; }
    download('exploit-tests.sol', lastPoC, 'text/plain;charset=utf-8');
    setLoading('پیش‌نویس PoC فاوندری دانلود شد (برای تکمیل و اجرا: forge test).');
  });

  btnRun.addEventListener('click', run);
})();
