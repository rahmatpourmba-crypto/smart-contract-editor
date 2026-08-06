// SPDX-License-Identifier: MIT
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

    constructor(string memory _name, string memory _symbol, uint256 initialSupply) {
        require(bytes(_name).length > 0, "Empty name");
        require(bytes(_symbol).length > 0, "Empty symbol");

        name        = _name;
        symbol      = _symbol;
        owner       = msg.sender;

        if (initialSupply > 0) {
            _mint(msg.sender, initialSupply);
        }
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
     * @notice Lock tokens for `account` until a future timestamp.
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
}
