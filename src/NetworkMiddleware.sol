// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/** 
 * @notice INetworkRegistry - Manages the registration and tracking of networks in the system
 * Handles network onboarding, verification, and maintenance of network status
 */
import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";

/** 
 * @notice INetworkMiddlewareService - Acts as an intermediary service layer between different components
 * Handles communication and coordination between various network parts
 * Manages middleware settings and configurations
 */
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";

/** 
 * @notice IVault - Manages the storage and handling of staked assets
 * Responsible for deposit/withdrawal functionality
 * Ensures secure custody of tokens or assets
 */
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

/** 
 * @notice ISlasher - Handles punishment mechanisms for malicious or misbehaving validators/operators
 * @notice IVetoSlasher - Provides mechanism to prevent or override slashing actions for governance/safety
 */
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";

/** 
 * @notice INetworkRestakeDelegator - Manages the delegation of staked assets
 * Handles restaking mechanism where staked assets can be redirected or re-delegated
 * Part of liquid staking/delegation system
 */
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";

//@notice IDefaultStakerRewards - Defines how rewards are distributed to users who stake assets
//@notice IDefaultOperatorRewards - Defines how rewards are distributed to operators/validators
import {IDefaultStakerRewards} from "@symbiotic-rewards/interfaces/defaultStakerRewards/IDefaultStakerRewards.sol";
import {IDefaultOperatorRewards} from "@symbiotic-rewards/interfaces/defaultOperatorRewards/IDefaultOperatorRewards.sol";

contract Network {
    constructor(
        INetworkRegistry networkRegistry,
        INetworkMiddlewareService middlewareService
    ) {
        networkRegistry.registerNetwork();
        middlewareService.setMiddleware(msg.sender);
    }
}

contract NetworkMiddleware is Ownable {

    INetworkRegistry public immutable networkRegistry;
    INetworkMiddlewareService public immutable middlewareService;

    event NetworkDeployed(uint32 domain, address network);

    IDefaultOperatorRewards public operatorRewards;

    constructor(IDefaultOperatorRewards _operatorRewards) Ownable(msg.sender) {
        operatorRewards = _operatorRewards;
    }

    function deployNetwork(uint32 domain) external returns (address network) {
        bytes32 salt = bytes32(uint256(domain));
        network = Create2.deploy(0, salt, _networkBytecode());
        emit NetworkDeployed(domain, network);
    }

    function getNetwork(uint32 domain) public view returns (address) {
        bytes32 salt = bytes32(uint256(domain));
        return Create2.computeAddress(salt, keccak256(_networkBytecode()));
    }

    function _networkBytecode() internal view returns (bytes memory) {
        return
            abi.encodePacked(
                type(Network).creationCode,
                abi.encode(networkRegistry, middlewareService)
            );
    }
}
