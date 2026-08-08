'use strict';

const VERSION_MAP = {
  '0.8.36': { local: 'solc/soljson-v0.8.36.js', remote: 'https://binaries.soliditylang.org/bin/soljson-v0.8.36+commit.8a079791.js' },
  '0.8.26': { local: null, remote: 'https://binaries.soliditylang.org/bin/soljson-v0.8.26+commit.8a97fa7a.js' },
  '0.8.20': { local: null, remote: 'https://binaries.soliditylang.org/bin/soljson-v0.8.20+commit.a1b79de6.js' },
  '0.8.10': { local: null, remote: 'https://binaries.soliditylang.org/bin/soljson-v0.8.10+commit.fc410830.js' },
  '0.8.0': { local: null, remote: 'https://binaries.soliditylang.org/bin/soljson-v0.8.0+commit.c7dfd78e.js' },
  '0.7.6': { local: null, remote: 'https://binaries.soliditylang.org/bin/soljson-v0.7.6+commit.7338295f.js' },
  '0.6.12': { local: null, remote: 'https://binaries.soliditylang.org/bin/soljson-v0.6.12+commit.27d51765.js' }
};

const DEFAULT_FILES = {
  'Simple.sol': `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private value;

    function set(uint256 newValue) public {
        value = newValue;
    }

    function get() public view returns (uint256) {
        return value;
    }
}
`,
  'Token.sol': `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract MyToken is IERC20 {
    string public name = "MyToken";
    string public symbol = "MTK";
    uint8 public decimals = 18;
    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;

    constructor() {
        _totalSupply = 1000000 * 10 ** decimals;
        _balances[msg.sender] = _totalSupply;
    }

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view override returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(_balances[msg.sender] >= amount, "Insufficient balance");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
`
};

// ---------- State ----------
let files = {};
let activeFile = null;
let editor = null;
let solc = null; // current compiler wrapper
let solcReady = false;

// ---------- Solc loading (runs inside a Web Worker) ----------
// Chrome refuses synchronous WebAssembly compilation on the main thread for
// buffers larger than 8MB. solc's wasm binary is ~16MB, so the emscripten
// runtime runs in a worker where that restriction does not apply.

const loadedCompiler = {};

async function loadCompiler(version) {
  const info = VERSION_MAP[version];
  if (!info) throw new Error('Unknown compiler version: ' + version);

  if (loadedCompiler[version]) {
    return loadedCompiler[version];
  }

  setSolcStatus('Loading solc ' + version + '...');

  const src = info.local || info.remote;
  const worker = new Worker('solc.worker.js');
  const wrapper = await workerLoadCompiler(worker, version, src);
  loadedCompiler[version] = wrapper;
  setSolcStatus('solc ' + version + ' ready');
  return wrapper;
}

function workerLoadCompiler(worker, version, src) {
  return new Promise((resolve, reject) => {
    let id = 0;
    const pending = new Map();
    worker.onmessage = (e) => {
      const msg = e.data;
      if (msg.type === 'ready') {
        resolve({
          version: () => version,
          compile: (inputJson) => new Promise((res, rej) => {
            const mid = ++id;
            pending.set(mid, { res, rej });
            worker.postMessage({ type: 'compile', id: mid, input: inputJson });
          })
        });
      } else if (msg.type === 'result') {
        const p = pending.get(msg.id);
        if (p) {
          pending.delete(msg.id);
          p.res(msg.output);
        }
      } else if (msg.type === 'error') {
        if (msg.id) {
          const p = pending.get(msg.id);
          if (p) {
            pending.delete(msg.id);
            p.rej(new Error(msg.message));
          }
        } else {
          reject(new Error(msg.message));
        }
      }
    };
    worker.onerror = (e) => reject(new Error('Worker error: ' + e.message));
    worker.postMessage({ type: 'load', src: src, version: version });
  });
}

// ---------- Compile ----------
async function compile() {
  if (!activeFile) return;
  if (!solcReady) {
    logError('Compiler is still loading. Please wait.');
    return;
  }
  const content = editor.getValue();
  const optimize = document.getElementById('chk-optimize').checked;
  const input = {
    language: 'Solidity',
    sources: {},
    settings: {
      optimizer: { enabled: optimize, runs: 200 },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode'] } }
    }
  };
  input.sources[activeFile] = { content: content };

  setOutput('errors', '<p class="muted">Compiling...</p>');
  clearOutput('abi', 'bytecode', 'deployed');

  try {
    const result = JSON.parse(await solc.compile(JSON.stringify(input)));
    renderOutput(result);
  } catch (e) {
    logError('Compilation crashed: ' + e.message);
  }
}

function renderOutput(result) {
  const errors = (result.errors || []).map(e => {
    const cls = e.severity === 'error' ? 'err' : e.severity === 'warning' ? 'warn' : 'info';
    const loc = e.sourceLocation ? `[${e.sourceLocation.file}:${e.sourceLocation.start}-${e.sourceLocation.end}] ` : '';
    return `<div class="msg ${cls}"><code>${escapeHtml(loc + e.formattedMessage || e.message)}</code></div>`;
  });

  if (errors.length) {
    setOutput('errors', errors.join(''));
  } else {
    setOutput('errors', '<p class="success">Compilation succeeded. No errors.</p>');
  }

  let abiJson = '—', bytecode = '—', deployed = '—', name = '';
  try {
    const source = result.contracts && result.contracts[activeFile];
    if (source) {
      const contractKeys = Object.keys(source);
      if (contractKeys.length) {
        name = contractKeys[0];
        const c = source[name];
        if (c.abi) abiJson = JSON.stringify(c.abi, null, 2);
        if (c.evm && c.evm.bytecode) bytecode = '0x' + c.evm.bytecode.object || '—';
        if (c.evm && c.evm.deployedBytecode) deployed = '0x' + c.evm.deployedBytecode.object || '—';
      }
    }
  } catch (e) { /* ignore */ }

  const fileLabel = name ? `${activeFile} (${name})` : activeFile;
  setOutput('abi', `<div class="panel-head">ABI — ${escapeHtml(fileLabel)}</div><pre>${escapeHtml(abiJson)}</pre>`);
  setOutput('bytecode', `<div class="panel-head">Bytecode — ${escapeHtml(fileLabel)}</div><pre>${escapeHtml(bytecode)}</pre>`);
  setOutput('deployed', `<div class="panel-head">Deployed Bytecode — ${escapeHtml(fileLabel)}</div><pre>${escapeHtml(deployed)}</pre>`);
}

// ---------- Files ----------
function persist() {
  try {
    localStorage.setItem('sce_files', JSON.stringify(files));
  } catch (e) { /* storage may be unavailable */ }
}

function loadPersisted() {
  try {
    const raw = localStorage.getItem('sce_files');
    if (raw) {
      files = JSON.parse(raw);
      return true;
    }
  } catch (e) { /* ignore */ }
  return false;
}

function refreshFileList() {
  const list = document.getElementById('file-list');
  list.innerHTML = '';
  Object.keys(files).forEach(name => {
    const li = document.createElement('li');
    li.textContent = name;
    li.classList.add('file-item');
    if (name === activeFile) li.classList.add('active');
    li.addEventListener('click', () => openFile(name));
    list.appendChild(li);
  });
}

function refreshTabs() {
  const tabs = document.getElementById('tabs');
  tabs.innerHTML = '';
  Object.keys(files).forEach(name => {
    const span = document.createElement('span');
    span.className = 'tab' + (name === activeFile ? ' active' : '');
    span.textContent = name;
    span.addEventListener('click', () => openFile(name));
    const close = document.createElement('button');
    close.className = 'tab-close';
    close.textContent = 'x';
    close.title = 'Close file';
    close.addEventListener('click', (e) => {
      e.stopPropagation();
      closeFile(name);
    });
    span.appendChild(close);
    tabs.appendChild(span);
  });
}

function openFile(name) {
  if (!files[name]) return;
  activeFile = name;
  editor.setValue(files[name]);
  editor.clearHistory();
  refreshFileList();
  refreshTabs();
}

function createFile() {
  let i = 1;
  let base = 'Contract';
  while (files[base + i + '.sol']) i++;
  const name = base + i + '.sol';
  files[name] = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract ' + base + i + ' {\n\n}\n';
  persist();
  refreshFileList();
  openFile(name);
}

function closeFile(name) {
  if (Object.keys(files).length === 1) {
    createFile();
  }
  delete files[name];
  if (activeFile === name) {
    activeFile = Object.keys(files)[0];
    editor.setValue(files[activeFile]);
    editor.clearHistory();
  }
  persist();
  refreshFileList();
  refreshTabs();
}

// ---------- UI helpers ----------
function setSolcStatus(text) {
  document.getElementById('solc-status').textContent = text;
}

function setOutput(panel, html) {
  document.getElementById('panel-' + panel).innerHTML = html;
}

function clearOutput() {
  const panels = ['errors', 'abi', 'bytecode', 'deployed'];
  panels.forEach(p => setOutput(p, '<p class="muted">—</p>'));
}

function logError(msg) {
  setOutput('errors', `<div class="msg err"><code>${escapeHtml(msg)}</code></div>`);
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ---------- Init ----------
function initEditor() {
  const mode = {
    name: 'clike',
    keywords: (
      'pragma solidity abstract contract interface library modifier event enum ' +
      'function public private internal external view pure payable constant ' +
      'returns return require revert if else for while do break continue ' +
      'mapping struct storage memory calldata indexed address bool string ' +
      'uint int bytes byte uint8 uint16 uint32 uint64 uint128 uint256 ' +
      'int8 int16 int32 int64 int128 int256 bytes1 bytes2 bytes32 ' +
      'new delete emit constructor selfdestruct receive fallback ' +
      'assembly let mstore mload add sub mul div sstore sload'
    ).split(' '),
    types: 'bool address uint int bytes string',
    blockKeywords: 'if else for while do',
    defKeywords: 'function modifier constructor contract interface library',
    atoms: 'true false null'
  };

  editor = CodeMirror(document.getElementById('editor-wrap'), {
    value: files[activeFile],
    mode: mode,
    theme: 'dracula',
    lineNumbers: true,
    lineWrapping: true,
    indentUnit: 4,
    smartIndent: true,
    tabSize: 4,
    autoCloseBrackets: true,
    matchBrackets: true,
    styleActiveLine: true,
    foldGutter: true,
    gutters: ['CodeMirror-linenumbers', 'CodeMirror-foldgutter']
  });
  editor.setOption('extraKeys', { 'Ctrl-S': () => compile() });
  editor.on('change', () => {
    if (activeFile) {
      files[activeFile] = editor.getValue();
      persist();
    }
  });
}

function setupEvents() {
  document.getElementById('btn-new-file').addEventListener('click', createFile);
  document.getElementById('btn-compile').addEventListener('click', compile);
  document.getElementById('chk-optimize').addEventListener('change', () => {
    persist();
  });

  document.getElementById('solc-version').addEventListener('change', async (e) => {
    const v = e.target.value;
    localStorage.setItem('sce_version', v);
    try {
      solc = await loadCompiler(v);
      solcReady = true;
    } catch (err) {
      setSolcStatus('Failed to load ' + v);
      solcReady = false;
    }
  });

  document.querySelectorAll('.out-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.out-tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.out-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('panel-' + btn.dataset.panel).classList.add('active');
    });
  });
}

async function main() {
  if (!loadPersisted()) {
    files = JSON.parse(JSON.stringify(DEFAULT_FILES));
  }
  activeFile = Object.keys(files)[0] || 'Simple.sol';
  if (!files[activeFile]) files[activeFile] = DEFAULT_FILES['Simple.sol'];
  persist();

  initEditor();
  setupEvents();
  refreshFileList();
  refreshTabs();

  const savedVersion = localStorage.getItem('sce_version');
  if (savedVersion && VERSION_MAP[savedVersion]) {
    document.getElementById('solc-version').value = savedVersion;
  }
  const v = document.getElementById('solc-version').value;
  try {
    solc = await loadCompiler(v);
    solcReady = true;
  } catch (err) {
    setSolcStatus('Failed to load compiler');
    solcReady = false;
  }
}

document.addEventListener('DOMContentLoaded', main);
