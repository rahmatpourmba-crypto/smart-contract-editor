'use strict';

// ============================================================
//  توکن ساز — ساخت قرارداد اختصاصی در مرورگر بدون ترمینال
//  قالب‌ها دقیقاً همان contracts/MyToken.sol و PremiumToken.sol
// ============================================================

const TEMPLATE_BASE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  MyToken - Premium ERC-20
 * @notice Standalone ERC-20 with Mint / Burn / Invest Lock / Ownership transfer.
 *         No external imports required (compiles in any Solidity 0.8.x toolchain).
 *
 *  SELLABLE FEATURES:
 *  - Standard ERC-20 (transfer, approve, transferFrom, allowance)
 *  - Owner-only minting
 *  - Public burn (anyone burns their own tokens)
 *  - Investor lock / vesting: owners can lock tokens for a period
 *  - Transfer of contract ownership
 *  - Reentrancy-safe design (no external calls in transfer paths)
 */
contract MyToken {
    string  public name;
    string  public symbol;
    uint8   public constant decimals = 18;

    uint256 public totalSupply;
    address public owner;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // address -> unlock timestamp (0 = not locked)
    mapping(address => uint256) public unlockTime;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Lock(address indexed holder, uint256 until);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // __BASE_CONSTRUCTOR__

    /* ============ VIEWS ============ */

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function allowance(address tokenOwner, address spender) public view returns (uint256) {
        return _allowances[tokenOwner][spender];
    }

    function isLocked(address account) public view returns (bool) {
        return unlockTime[account] > block.timestamp;
    }

    /* ============ ERC-20 TRANSFER ============ */

    function transfer(address to, uint256 amount) public returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        require(spender != address(0), "Approve to zero");
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= amount, "Allowance exceeded");
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        uint256 current = _allowances[msg.sender][spender];
        _allowances[msg.sender][spender] = current + addedValue;
        emit Approval(msg.sender, spender, current + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {
        uint256 current = _allowances[msg.sender][spender];
        require(current >= subtractedValue, "Allowance below zero");
        _allowances[msg.sender][spender] = current - subtractedValue;
        emit Approval(msg.sender, spender, current - subtractedValue);
        return true;
    }

    /* ============ MINT / BURN ============ */

    function mint(address to, uint256 amount) public onlyOwner returns (bool) {
        _mint(to, amount);
        return true;
    }

    function burn(uint256 amount) public returns (bool) {
        _burn(msg.sender, amount);
        return true;
    }

    function burnFrom(address from, uint256 amount) public returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= amount, "Allowance exceeded");
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - amount;
        }
        _burn(from, amount);
        return true;
    }

    /* ============ INVESTOR LOCK / VESTING ============ */

    /**
     * @notice Lock tokens for \`account\` until a future timestamp.
     * @param account     Holder to lock.
     * @param releaseTime Unix timestamp (seconds) when tokens unlock.
     * @dev Only owner can create/extend a lock. Locked tokens cannot be
     *      transferred (but CAN be burned to avoid dead capital).
     */
    function lock(address account, uint256 releaseTime) public onlyOwner {
        require(releaseTime > block.timestamp, "Release must be future");
        require(_balances[account] > 0, "No balance to lock");
        unlockTime[account] = releaseTime;
        emit Lock(account, releaseTime);
    }

    /**
     * @notice Manually unlock (release) tokens early. Only owner.
     */
    function forceUnlock(address account) public onlyOwner {
        delete unlockTime[account];
        emit Lock(account, block.timestamp);
    }

    /* ============ OWNERSHIP ============ */

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Owner to zero");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /* ============ INTERNAL ============ */

    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "Mint to zero");
        require(amount > 0, "Mint zero");
        totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
        emit Mint(to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        require(from != address(0), "Burn from zero");
        require(amount > 0, "Burn zero");
        require(_balances[from] >= amount, "Burn exceeds balance");
        _balances[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
        emit Burn(from, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "Transfer from zero");
        require(to != address(0), "Transfer to zero");
        require(amount > 0, "Transfer zero");
        require(_balances[from] >= amount, "Insufficient balance");
        require(!isLocked(from), "Tokens locked");

        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
}`;

const TEMPLATE_PREMIUM = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  PremiumToken - Premium ERC-20 with tax, auto-burn, anti-whale + custom features
 * @notice Standalone ERC-20 (no imports) with advanced sellable features:
 *         - Transfer tax (basis points) collected on every taxable transfer
 *         - Optional separate Buy / Sell tax (requires a pair address)
 *         - Auto-burn: a share of the collected tax is permanently burned
 *         - Anti-whale: configurable max holding percentage per wallet
 *         - Max-tx: configurable max amount per transfer
 *         - Whitelist mode: only approved addresses can transfer
 *         - Pausable: owner can pause/unpause all transfers
 *         - Blacklist: owner can block specific addresses
 *         - Tax exclusions (exchanges, liquidity, deployer)
 *         - Owner toggle to enable/disable the whole tax system
 *         - Classic mint / burn / investor lock / ownership transfer
 */

contract PremiumToken {
    string  public name;
    string  public symbol;
    uint8   public constant decimals = 18;

    uint256 public totalSupply;
    address public owner;
    address public marketingWallet;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // Investor lock: address -> unlock timestamp (0 = not locked)
    mapping(address => uint256) public unlockTime;

    // -------- TAX --------
    uint256 public transferTax;        // basis points: 500 = 5%
    uint256 public burnShare;          // percent of tax that is burned: 30 = 30%
    bool    public taxEnabled = true;

    // -------- BUY/SELL TAX (optional, requires pair) --------
    address public pair;               // AMM pair address; address(0) = disabled
    uint256 public buyTax;             // basis points applied when from == pair
    uint256 public sellTax;            // basis points applied when to == pair

    // -------- ANTI-WHALE / MAX-TX --------
    uint256 public maxWalletPercent;   // percent of supply: 200 = 2%
    bool    public antiWhaleEnabled = true;
    uint256 public maxTxPercent;       // percent of supply per transfer: 0 = unlimited

    // -------- WHITELIST --------
    bool    public whitelistEnabled;
    mapping(address => bool) public isWhitelisted;

    // -------- PAUSE --------
    bool    public paused;

    // -------- BLACKLIST --------
    mapping(address => bool) public isBlacklisted;

    // -------- EXCLUSIONS --------
    mapping(address => bool) public isTaxExcluded;      // no tax on transfers from/to
    mapping(address => bool) public isWhaleExempt;      // can hold more than cap / bypass whitelist

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed tokenOwner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Lock(address indexed holder, uint256 until);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TaxChanged(uint256 transferTax, uint256 burnShare);
    event BuySellTaxChanged(uint256 buyTax, uint256 sellTax);
    event MarketingWalletChanged(address indexed wallet);
    event TaxToggled(bool enabled);
    event PairChanged(address indexed pair);
    event AntiWhaleChanged(uint256 maxWalletPercent, bool enabled);
    event MaxTxChanged(uint256 maxTxPercent);
    event WhitelistToggled(bool enabled);
    event Whitelisted(address indexed account, bool state);
    event Paused(bool state);
    event Blacklisted(address indexed account, bool state);
    event Excluded(address indexed account, bool state);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // __PREMIUM_CONSTRUCTOR__

    /* ============ VIEWS ============ */

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function allowance(address tokenOwner, address spender) public view returns (uint256) {
        return _allowances[tokenOwner][spender];
    }

    function isLocked(address account) public view returns (bool) {
        return unlockTime[account] > block.timestamp;
    }

    function maxWalletAmount() public view returns (uint256) {
        return (totalSupply * maxWalletPercent) / 10000;
    }

    function maxTxAmount() public view returns (uint256) {
        if (maxTxPercent == 0) return type(uint256).max;
        return (totalSupply * maxTxPercent) / 10000;
    }

    /* ============ ERC-20 TRANSFER ============ */

    function transfer(address to, uint256 amount) public returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        require(spender != address(0), "Approve to zero");
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= amount, "Allowance exceeded");
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        uint256 current = _allowances[msg.sender][spender];
        _allowances[msg.sender][spender] = current + addedValue;
        emit Approval(msg.sender, spender, current + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {
        uint256 current = _allowances[msg.sender][spender];
        require(current >= subtractedValue, "Allowance below zero");
        _allowances[msg.sender][spender] = current - subtractedValue;
        emit Approval(msg.sender, spender, current - subtractedValue);
        return true;
    }

    /* ============ MINT / BURN ============ */

    function mint(address to, uint256 amount) public onlyOwner returns (bool) {
        _mint(to, amount);
        return true;
    }

    function burn(uint256 amount) public returns (bool) {
        _burn(msg.sender, amount);
        return true;
    }

    function burnFrom(address from, uint256 amount) public returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= amount, "Allowance exceeded");
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - amount;
        }
        _burn(from, amount);
        return true;
    }

    /* ============ INVESTOR LOCK ============ */

    function lock(address account, uint256 releaseTime) public onlyOwner {
        require(releaseTime > block.timestamp, "Release must be future");
        require(_balances[account] > 0, "No balance to lock");
        unlockTime[account] = releaseTime;
        emit Lock(account, releaseTime);
    }

    function forceUnlock(address account) public onlyOwner {
        delete unlockTime[account];
        emit Lock(account, block.timestamp);
    }

    /* ============ OWNERSHIP ============ */

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Owner to zero");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /* ============ ADMIN: TAX ============ */

    function setTax(uint256 _transferTax, uint256 _burnShare) public onlyOwner {
        require(_transferTax <= 2500, "Tax max 25%");
        require(_burnShare <= 100, "Burn share max 100");
        transferTax = _transferTax;
        burnShare = _burnShare;
        emit TaxChanged(_transferTax, _burnShare);
    }

    function setBuySellTax(uint256 _buyTax, uint256 _sellTax) public onlyOwner {
        require(_buyTax <= 2500, "Buy tax max 25%");
        require(_sellTax <= 2500, "Sell tax max 25%");
        buyTax = _buyTax;
        sellTax = _sellTax;
        emit BuySellTaxChanged(_buyTax, _sellTax);
    }

    function setMarketingWallet(address wallet) public onlyOwner {
        require(wallet != address(0), "Wallet zero");
        marketingWallet = wallet;
        emit MarketingWalletChanged(wallet);
    }

    function setTaxEnabled(bool state) public onlyOwner {
        taxEnabled = state;
        emit TaxToggled(state);
    }

    function setExcluded(address account, bool state) public onlyOwner {
        isTaxExcluded[account] = state;
        emit Excluded(account, state);
    }

    /* ============ ADMIN: PAIR (buy/sell tax) ============ */

    function setPair(address _pair) public onlyOwner {
        pair = _pair;
        emit PairChanged(_pair);
    }

    /* ============ ADMIN: ANTI-WHALE / MAX-TX ============ */

    function setAntiWhale(uint256 _maxWalletPercent, bool _enabled) public onlyOwner {
        require(_maxWalletPercent >= 1, "Min 0.01%");
        maxWalletPercent = _maxWalletPercent;
        antiWhaleEnabled = _enabled;
        emit AntiWhaleChanged(_maxWalletPercent, _enabled);
    }

    function setWhaleExempt(address account, bool state) public onlyOwner {
        isWhaleExempt[account] = state;
    }

    function setMaxTx(uint256 _maxTxPercent) public onlyOwner {
        require(_maxTxPercent <= 10000, "Max 100%");
        maxTxPercent = _maxTxPercent;
        emit MaxTxChanged(_maxTxPercent);
    }

    /* ============ ADMIN: WHITELIST ============ */

    function setWhitelistEnabled(bool state) public onlyOwner {
        whitelistEnabled = state;
        emit WhitelistToggled(state);
    }

    function setWhitelisted(address account, bool state) public onlyOwner {
        isWhitelisted[account] = state;
        emit Whitelisted(account, state);
    }

    /* ============ ADMIN: PAUSE ============ */

    function setPaused(bool state) public onlyOwner {
        paused = state;
        emit Paused(state);
    }

    /* ============ ADMIN: BLACKLIST ============ */

    function setBlacklisted(address account, bool state) public onlyOwner {
        isBlacklisted[account] = state;
        emit Blacklisted(account, state);
    }

    /* ============ INTERNAL ============ */

    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "Mint to zero");
        require(amount > 0, "Mint zero");
        totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
        emit Mint(to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        require(from != address(0), "Burn from zero");
        require(amount > 0, "Burn zero");
        require(_balances[from] >= amount, "Burn exceeds balance");
        _balances[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
        emit Burn(from, amount);
    }

    function _resolveTax(address from, address to) internal view returns (uint256) {
        if (pair == address(0)) return transferTax;
        if (to == pair) return sellTax > 0 ? sellTax : transferTax;
        if (from == pair) return buyTax > 0 ? buyTax : transferTax;
        return transferTax;
    }

    function _checkMaxWallet(address to, uint256 amount) internal view {
        if (!antiWhaleEnabled) return;
        if (isWhaleExempt[to]) return;
        if (to == pair) return;
        require(_balances[to] + amount <= maxWalletAmount(), "Max wallet exceeded");
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "Transfer from zero");
        require(to != address(0), "Transfer to zero");
        require(amount > 0, "Transfer zero");
        require(!paused, "Transfers paused");
        require(!isBlacklisted[from] && !isBlacklisted[to], "Blacklisted");
        require(_balances[from] >= amount, "Insufficient balance");
        require(!isLocked(from), "Tokens locked");

        if (whitelistEnabled) {
            require(isWhaleExempt[from] || isWhitelisted[from] || from == owner || from == pair, "Sender not whitelisted");
            require(from == owner || isWhaleExempt[to] || isWhitelisted[to] || to == owner || to == pair, "Receiver not whitelisted");
        }

        if (maxTxPercent > 0) {
            require(amount <= maxTxAmount(), "Max tx exceeded");
        }

        _checkMaxWallet(to, amount);

        bool applyTax = taxEnabled
            && !isTaxExcluded[from]
            && !isTaxExcluded[to];

        uint256 taxRate = applyTax ? _resolveTax(from, to) : 0;
        uint256 taxAmount = (amount * taxRate) / 10000;
        uint256 burnPart = (taxAmount * burnShare) / 100;
        uint256 feeToWallet = taxAmount - burnPart;
        uint256 amountOut = amount - taxAmount;

        _balances[from] -= amount;
        if (burnPart > 0) {
            _balances[address(0)] += burnPart;
            totalSupply -= burnPart;
            emit Burn(from, burnPart);
        }
        if (feeToWallet > 0) {
            _balances[marketingWallet] += feeToWallet;
        }
        _balances[to] += amountOut;

        emit Transfer(from, to, amountOut);
        if (feeToWallet > 0) emit Transfer(from, marketingWallet, feeToWallet);
    }
}
`;

// ---------- helpers ----------

function sanitize(s) {
  return String(s).replace(/[^A-Za-z0-9]/g, '');
}

function cleanQuotes(s) {
  return String(s).replace(/["\\]/g, '');
}

function ownerExpr(addr) {
  if (!addr) return 'msg.sender';
  return 'address(uint160(' + BigInt('0x' + addr.slice(2)).toString() + '))';
}

// ---------- generator ----------

function buildToken(opts) {
  const isPremium = opts.mode === 'premium';
  const template = isPremium ? TEMPLATE_PREMIUM : TEMPLATE_BASE;
  const contractClass = isPremium ? 'PremiumToken' : 'MyToken';
  const contractName = sanitize(opts.symbol) + 'Token';
  const ownerE = ownerExpr(opts.owner);
  const supplyRaw = String(opts.supply) === '0' ? '0' : String(opts.supply) + ' * 10 ** 18';
  const supplyLines = String(opts.supply) === '0'
    ? []
    : [
        '        if (' + supplyRaw + ' > 0) {',
        '            _mint(' + ownerE + ', ' + supplyRaw + ');',
        '        }'
      ];

  let src = template.replace(new RegExp('contract ' + contractClass + '\\s*\\{'), 'contract ' + contractName + ' {');

  let ctor;
  if (isPremium) {
    const taxBp = opts.tax === 0 ? '0' : String(opts.tax * 100);
    const whaleBp = opts.whale === 0 ? '0' : String(opts.whale * 100);
    const antiWhale = opts.whale === 0 ? 'false' : 'true';
    const buyBp = opts.buysell ? String(opts.buytax * 100) : '0';
    const sellBp = opts.buysell ? String(opts.selltax * 100) : '0';
    ctor = [
      '    constructor() {',
      '        name            = "' + cleanQuotes(opts.name) + '";',
      '        symbol          = "' + cleanQuotes(opts.symbol) + '";',
      '        owner           = ' + ownerE + ';',
      '        marketingWallet = ' + ownerE + ';',
      '        transferTax     = ' + taxBp + ';',
      '        burnShare       = ' + opts.burn + ';',
      '        maxWalletPercent= ' + whaleBp + ';',
      '        buyTax          = ' + buyBp + ';',
      '        sellTax         = ' + sellBp + ';',
      '        maxTxPercent    = ' + (opts.maxTx * 100) + ';',
      '        whitelistEnabled= ' + (opts.whitelist ? 'true' : 'false') + ';',
      '        taxEnabled      = true;',
      '        antiWhaleEnabled= ' + antiWhale + ';',
      '        isTaxExcluded[' + ownerE + '] = true;',
      '        isWhaleExempt[' + ownerE + '] = true;'
    ].concat(supplyLines, ['    }']).join('\n');
  } else {
    ctor = [
      '    constructor() {',
      '        require(bytes("' + cleanQuotes(opts.name) + '").length > 0, "Empty name");',
      '        require(bytes("' + cleanQuotes(opts.symbol) + '").length > 0, "Empty symbol");',
      '',
      '        name   = "' + cleanQuotes(opts.name) + '";',
      '        symbol = "' + cleanQuotes(opts.symbol) + '";',
      '        owner  = ' + ownerE + ';'
    ].concat(supplyLines, ['    }']).join('\n');
  }

  const marker = isPremium ? '    // __PREMIUM_CONSTRUCTOR__' : '    // __BASE_CONSTRUCTOR__';
  if (src.indexOf(marker) === -1) {
    throw new Error('قالب قرارداد خراب است (مارکر constructor پیدا نشد).');
  }
  src = src.replace(marker, ctor);

  // بنر قابلیت‌های سفارشی (فقط پریمیوم)
  if (isPremium) {
    const feat = [];
    if (opts.whitelist) feat.push('whitelist/presale');
    if (opts.buysell) feat.push('buy/sell tax');
    if (opts.maxTx > 0) feat.push('max-tx');
    if (opts.pausable) feat.push('pausable');
    if (opts.blacklist) feat.push('blacklist');
    if (feat.length) {
      src = src.replace(
        'pragma solidity ^0.8.20;',
        'pragma solidity ^0.8.20;\n\n// CUSTOM FEATURES: ' + feat.join(', ')
      );
    }
  }

  return { src: src, fileName: contractName + '.sol' };
}

// ---------- UI wiring ----------

let lastGenerated = null;

function downloadFile(fileName, content) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(url); }, 150);
}

function setGenStatus(html, cls) {
  const el = document.getElementById('gen-status');
  el.innerHTML = html;
  el.className = 'gen-status ' + (cls || '');
}

function readOpts() {
  const name = document.getElementById('gen-name').value.trim();
  const symbol = document.getElementById('gen-symbol').value.trim();
  const supply = parseInt(document.getElementById('gen-supply').value, 10);
  const owner = document.getElementById('gen-owner').value.trim();
  const mode = document.querySelector('input[name="gen-mode"]:checked').value;
  const tax = parseInt(document.getElementById('gen-tax').value, 10);
  const burn = parseInt(document.getElementById('gen-burn').value, 10);
  const whale = parseInt(document.getElementById('gen-whale').value, 10);
  const maxTx = parseInt(document.getElementById('gen-maxtx').value, 10);
  const whitelist = document.getElementById('gen-whitelist').checked;
  const buysell = document.getElementById('gen-buysell').checked;
  const buytax = parseInt(document.getElementById('gen-buytax').value, 10);
  const selltax = parseInt(document.getElementById('gen-selltax').value, 10);
  const pausable = document.getElementById('gen-pausable').checked;
  const blacklist = document.getElementById('gen-blacklist').checked;

  if (!name) { setGenStatus('❌ نام توکن را وارد کن.', 'err'); return null; }
  if (!sanitize(symbol)) { setGenStatus('❌ نماد باید فقط حروف/اعداد انگلیسی باشد.', 'err'); return null; }
  if (isNaN(supply) || supply < 0) { setGenStatus('❌ عرضه اولیه عدد نامعتبر است.', 'err'); return null; }
  if (owner && !/^0x[0-9a-fA-F]{40}$/.test(owner)) { setGenStatus('❌ آدرس مالک باید 0x + 40 کاراکتر هگز باشد.', 'err'); return null; }
  if (mode === 'premium') {
    if (isNaN(tax) || tax < 0 || tax > 25) { setGenStatus('❌ مالیات باید بین ۰ تا ۲۵٪ باشد.', 'err'); return null; }
    if (isNaN(burn) || burn < 0 || burn > 100) { setGenStatus('❌ سوزاندن باید بین ۰ تا ۱۰۰٪ باشد.', 'err'); return null; }
    if (isNaN(whale) || whale < 0) { setGenStatus('❌ سقف نهنگ باید عدد مثبت باشد (۰ = غیرفعال).', 'err'); return null; }
    if (isNaN(maxTx) || maxTx < 0 || maxTx > 100) { setGenStatus('❌ سقف هر تراکنش باید بین ۰ تا ۱۰۰٪ باشد.', 'err'); return null; }
    if (buysell && (isNaN(buytax) || isNaN(selltax) || buytax < 0 || buytax > 25 || selltax < 0 || selltax > 25)) {
      setGenStatus('❌ مالیات خرید/فروش باید بین ۰ تا ۲۵٪ باشد.', 'err'); return null;
    }
  }
  return {
    name: cleanQuotes(name), symbol: cleanQuotes(symbol), supply: supply, owner: owner, mode: mode,
    tax: tax || 0, burn: burn || 0, whale: whale || 0,
    maxTx: maxTx || 0, whitelist: whitelist, buysell: buysell, buytax: buytax || 0, selltax: selltax || 0,
    pausable: pausable, blacklist: blacklist
  };
}

function doGenerate() {
  const opts = readOpts();
  if (!opts) return;
  setGenStatus('⏳ در حال ساخت قرارداد...');

  let result;
  try {
    result = buildToken(opts);
  } catch (e) {
    setGenStatus('❌ ' + e.message, 'err');
    return;
  }

  let fileName = result.fileName;
  let i = 1;
  while (files[fileName]) { fileName = result.fileName.replace('.sol', '') + '_' + i + '.sol'; i++; }

  files[fileName] = result.src;
  persist();
  refreshFileList();
  refreshTabs();
  openFile(fileName);

  lastGenerated = { fileName: fileName, src: result.src };

  // کامپایل خودکار
  setTimeout(function () { compile(); }, 150);

  const premiumNote = opts.mode === 'premium'
    ? ' · مالیات ' + opts.tax + '٪ · سوزاندن ' + opts.burn + '٪ · سقف نهنگ ' + (opts.whale === 0 ? 'خاموش' : opts.whale + '٪') : '';
  setGenStatus(
    '✅ ساخته شد: <b>' + fileName + '</b>' + premiumNote +
    '<br>کد در ادیتور باز شد و کامپایل خودکار انجام می‌شود. ' +
    '<br>این فایل آماده تحویل به مشتری است.',
    'ok'
  );
  document.getElementById('gen-download').classList.remove('hidden');
}

function doDownload() {
  if (lastGenerated) {
    downloadFile(lastGenerated.fileName, lastGenerated.src);
  }
}

function setupGenerator() {
  const modal = document.getElementById('gen-modal');
  const openBtn = document.getElementById('btn-generator');
  const closeBtn = document.getElementById('gen-close');
  const closeBtn2 = document.getElementById('gen-close2');
  const buildBtn = document.getElementById('gen-build');
  const dlBtn = document.getElementById('gen-download');
  const dlToolbar = document.getElementById('btn-download');
  const modeInputs = document.querySelectorAll('input[name="gen-mode"]');
  const premiumFields = document.getElementById('gen-premium-fields');
  const buysellChk = document.getElementById('gen-buysell');
  const buysellFields = document.getElementById('gen-buysell-fields');

  function openModal() {
    modal.classList.remove('hidden');
    lastGenerated = null;
    setGenStatus('');
    document.getElementById('gen-download').classList.add('hidden');
  }
  function closeModal() { modal.classList.add('hidden'); }

  function onMode() {
    const val = document.querySelector('input[name="gen-mode"]:checked').value;
    premiumFields.classList.toggle('hidden', val !== 'premium');
    buysellFields.classList.toggle('hidden', !(val === 'premium' && buysellChk.checked));
  }

  openBtn.addEventListener('click', openModal);
  closeBtn.addEventListener('click', closeModal);
  closeBtn2.addEventListener('click', closeModal);
  modal.addEventListener('click', function (e) { if (e.target === modal) closeModal(); });
  buildBtn.addEventListener('click', doGenerate);
  dlBtn.addEventListener('click', doDownload);
  dlToolbar.addEventListener('click', function () {
    if (activeFile) downloadFile(activeFile, files[activeFile]);
  });
  modeInputs.forEach(function (r) { r.addEventListener('change', onMode); });
  buysellChk.addEventListener('change', onMode);
  onMode();
}

document.addEventListener('DOMContentLoaded', setupGenerator);
