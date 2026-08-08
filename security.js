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
  const loading = document.getElementById('sec-loading');
  const report = document.getElementById('sec-report');

  let lastMarkdown = '';
  let lastGenerated = null;

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
    btnCopy.classList.add('hidden');
    report.innerHTML = '';
    setLoading('⏳ در حال تحلیل امنیتی (کامپایل + اسکن استاتیک + اکسپلویت در EVM مرورگر)...');

    const statics = [];
    try {
      const mod = await import('./security-test.js');
      const fileLabel = lastGenerated && lastGenerated.fileName ? lastGenerated.fileName : 'Security.sol';
      const input = {
        language: 'Solidity',
        sources: {},
        settings: {
          optimizer: { enabled: document.getElementById('chk-optimize').checked, runs: 200 },
          outputSelection: { '*': { '*': ['abi', 'evm.bytecode'] } }
        }
      };
      input.sources[fileLabel] = { content: src };

      let abi = null;
      let bytecode = null;
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
      } catch (e) {
        compileErrors = [{ formattedMessage: e.message }];
      }

      const staticFindings = mod.staticScan(src);
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
      render(compiled, mod);
      lastMarkdown = mod.reportToMarkdown(compiled, lastGenerated && lastGenerated.fileName || 'Security.sol');
      setLoading('');
    } catch (e) {
      setLoading('❌ خطا: ' + e.message);
    } finally {
      btnRun.disabled = false;
    }
  }

  function render(rep, mod) {
    const html = [];
    const h = (s) => { html.push(s); };

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
        h('<div class="sec-finding ' + SEV[sev].cls + '">');
        h('<div class="sec-f-head">');
        h('<span class="sev-badge ' + SEV[sev].cls + '">' + SEV[sev].label + '</span>');
        h('<span class="sec-f-title">' + (isDyn ? '🧪 ' : '📄 ') + escapeHtml(f.title) + '</span>');
        h('<span class="sec-f-kind">' + (isDyn ? 'پویا (EVM)' : 'استاتیک' + (f.line ? ' — خط ' + f.line : '')) + '</span>');
        h('</div>');
        h('<div class="sec-f-detail">' + escapeHtml(f.detail) + '</div>');
        if (f.fix) h('<div class="sec-f-fix">🛠 راه‌حل: ' + escapeHtml(f.fix) + '</div>');
        h('</div>');
      });
    });

    h('<div class="sec-disclaimer">این تحلیل خودکار به کمک قوانین استاتیک و شبیه‌سازی حمله در EVM مرورگر انجام شده و جایگزین حسابرسی انسانی حرفه‌ای نیست. نتایج را برای معامله‌های مهم با یک حسابرس مستقل تأیید کنید.</div>');

    report.innerHTML = html.join('');
    btnCopy.classList.remove('hidden');
  }

  btnCopy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(lastMarkdown);
      setLoading('گزارش Markdown کپی شد.');
    } catch (e) {
      setLoading('کپی ناموفق: ' + e.message);
    }
  });

  btnRun.addEventListener('click', run);
})();
