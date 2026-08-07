// SPDX-License-Identifier: MIT
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

    constructor() {
        // __PREMIUM_CONSTRUCTOR__
    }

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
