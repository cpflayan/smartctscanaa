// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

// A deliberately vulnerable contract for testing the scanner

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;

    // Vulnerability: no access control on constructor-like init
    function initialize() public {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    // Vulnerability: Reentrancy - state update after external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call BEFORE state update = reentrancy risk
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call
        balances[msg.sender] -= amount;
    }

    // Vulnerability: tx.origin authentication
    function withdrawAll() public {
        require(tx.origin == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    // Vulnerability: unchecked send
    function refundUser(address user, uint256 amount) public {
        balances[user].send(amount);
    }

    // Vulnerability: block.timestamp dependence
    function isLucky() public view returns (bool) {
        return block.timestamp % 2 == 0;
    }

    // Vulnerability: delegatecall to user-controlled address
    function upgradeTo(address newImpl) public {
        (bool success, ) = newImpl.delegatecall(
            abi.encodeWithSignature("upgrade()")
        );
        require(success);
    }

    // Vulnerability: selfdestruct without proper access control
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    // Vulnerability: hardcoded address
    function setOracle() public {
        address oracle = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    }

    // Vulnerability: no zero address check
    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    // Vulnerability: sha3 deprecated
    function hashData(bytes memory data) public pure returns (bytes32) {
        return sha3(data);
    }

    // Vulnerability: integer overflow (pre-0.8.0)
    function addBalance(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // No overflow check in Solidity <0.8
    }
}
