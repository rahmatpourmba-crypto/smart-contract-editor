// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  PremiumToken - Premium ERC-20 with tax, auto-burn, anti-whale
 * @notice Standalone ERC-20 (no imports) with advanced sellable features:
 *         - Transfer tax (basis points) collected on every taxable transfer
 *         - Auto-burn: a share of the collected tax is permanently burned
 *         - Anti-whale: configurable max holding percentage per wallet
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

    // -------- ANTI-WHALE --------
    uint256 public maxWalletPercent;   // percent of supply: 200 = 2%
    bool    public antiWhaleEnabled = true;

    // -------- EXCLUSIONS --------
    mapping(address => bool) public isTaxExcluded;      // no tax on transfers from/to
    mapping(address => bool) public isWhaleExempt;      // can hold more than cap

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed tokenOwner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Lock(address indexed holder, uint256 until);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TaxChanged(uint256 transferTax, uint256 burnShare);
    event MarketingWalletChanged(address indexed wallet);
    event TaxToggled(bool enabled);
    event AntiWhaleChanged(uint256 maxWalletPercent, bool enabled);
    event Excluded(address indexed account, bool state);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        require(bytes(name).length > 0, "Empty name");
        require(bytes(symbol).length > 0, "Empty symbol");
        owner       = msg.sender;
        marketingWallet = msg.sender;
        isTaxExcluded[msg.sender] = true;
        isWhaleExempt[msg.sender] = true;
        // مقادیر زیر توسط سازنده (make-token) جایگزین می‌شوند
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

    /* ============ ADMIN: ANTI-WHALE ============ */

    function setAntiWhale(uint256 _maxWalletPercent, bool _enabled) public onlyOwner {
        require(_maxWalletPercent >= 1, "Min 0.01%");
        maxWalletPercent = _maxWalletPercent;
        antiWhaleEnabled = _enabled;
        emit AntiWhaleChanged(_maxWalletPercent, _enabled);
    }

    function setWhaleExempt(address account, bool state) public onlyOwner {
        isWhaleExempt[account] = state;
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

    function _checkMaxWallet(address to, uint256 amount) internal view {
        if (!antiWhaleEnabled) return;
        if (isWhaleExempt[to]) return;
        require(_balances[to] + amount <= maxWalletAmount(), "Max wallet exceeded");
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "Transfer from zero");
        require(to != address(0), "Transfer to zero");
        require(amount > 0, "Transfer zero");
        require(_balances[from] >= amount, "Insufficient balance");
        require(!isLocked(from), "Tokens locked");

        _checkMaxWallet(to, amount);

        bool applyTax = taxEnabled
            && !isTaxExcluded[from]
            && !isTaxExcluded[to]
            && transferTax > 0;

        uint256 taxAmount = applyTax ? (amount * transferTax) / 10000 : 0;
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
