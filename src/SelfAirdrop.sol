// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SelfVerificationRoot} from "@self/contracts/abstract/SelfVerificationRoot.sol";
import {IVcAndDiscloseCircuitVerifier} from "@self/contracts/interfaces/IVcAndDiscloseCircuitVerifier.sol";
import {IIdentityVerificationHubV1} from "@self/contracts/interfaces/IIdentityVerificationHubV1.sol";
import {CircuitConstants} from "@self/contracts/constants/CircuitConstants.sol";
import {Formatter} from "@self/contracts/libraries/Formatter.sol";
import {CircuitAttributeHandler} from "@self/contracts/libraries/CircuitAttributeHandler.sol";

contract SelfAirdrop is SelfVerificationRoot {
    mapping(uint256 => uint256) internal _nullifiers;
    mapping(uint256 => bool) internal _registeredUserIdentifiers;
    mapping(address user => uint256 claimableTimestamp)
        public s_claimableTimestamp;

    error RegisteredNullifier();
    error InvalidUserIdentifier();

    event UserIdentifierRegistered(
        uint256 indexed registeredUserIdentifier,
        uint256 indexed nullifier
    );

    constructor(
        address _identityVerificationHub,
        uint256 _scope,
        uint256 _attestationId,
        bool _olderThanEnabled,
        uint256 _olderThan,
        bool _forbiddenCountriesEnabled,
        uint256[4] memory _forbiddenCountriesListPacked,
        bool[3] memory _ofacEnabled
    )
        SelfVerificationRoot(
            _identityVerificationHub, // Address of our Verification Hub, e.g., "0x77117D60eaB7C044e785D68edB6C7E0e134970Ea"
            _scope, // An application-specific identifier for the integrated contract
            _attestationId, // The id specifying the type of document to verify (e.g., 1 for passports)
            _olderThanEnabled, // Flag to enable age verification
            _olderThan, // The minimum age required for verification
            _forbiddenCountriesEnabled, // Flag to enable forbidden countries verification
            _forbiddenCountriesListPacked, // Packed data representing the list of forbidden countries
            _ofacEnabled // Flag to enable OFAC check
        )
    {}

    function verifySelfProof(
        IVcAndDiscloseCircuitVerifier.VcAndDiscloseProof memory proof
    ) public override {
        if (
            _scope !=
            proof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_SCOPE_INDEX]
        ) {
            revert InvalidScope();
        }

        if (
            _attestationId !=
            proof.pubSignals[
                CircuitConstants.VC_AND_DISCLOSE_ATTESTATION_ID_INDEX
            ]
        ) {
            revert InvalidAttestationId();
        }

        if (
            _nullifiers[
                proof.pubSignals[
                    CircuitConstants.VC_AND_DISCLOSE_NULLIFIER_INDEX
                ]
            ] != 0
        ) {
            revert RegisteredNullifier();
        }

        if (
            proof.pubSignals[
                CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX
            ] == 0
        ) {
            revert InvalidUserIdentifier();
        }

        IIdentityVerificationHubV1.VcAndDiscloseVerificationResult
            memory result = _identityVerificationHub.verifyVcAndDisclose(
                IIdentityVerificationHubV1.VcAndDiscloseHubProof({
                    olderThanEnabled: _verificationConfig.olderThanEnabled,
                    olderThan: _verificationConfig.olderThan,
                    forbiddenCountriesEnabled: _verificationConfig
                        .forbiddenCountriesEnabled,
                    forbiddenCountriesListPacked: _verificationConfig
                        .forbiddenCountriesListPacked,
                    ofacEnabled: _verificationConfig.ofacEnabled,
                    vcAndDiscloseProof: proof
                })
            );

        _nullifiers[result.nullifier] = proof.pubSignals[
            CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX
        ];
        _registeredUserIdentifiers[
            proof.pubSignals[
                CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX
            ]
        ] = true;

        updateClaimableTimestamp(result.revealedDataPacked);

        emit UserIdentifierRegistered(
            proof.pubSignals[
                CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX
            ],
            result.nullifier
        );
    }

    function updateClaimableTimestamp(
        uint256[3] memory revealedDataPacked
    ) internal {
        bytes memory charcodes = Formatter.fieldElementsToBytes(
            revealedDataPacked
        );
        string memory expiryDate = CircuitAttributeHandler.getExpiryDate(
            charcodes
        );

        bytes memory expiryBytes = bytes(expiryDate);
        bytes memory dayBytes = new bytes(2);
        bytes memory monthBytes = new bytes(2);
        bytes memory yearBytes = new bytes(2);

        dayBytes[0] = expiryBytes[0];
        dayBytes[1] = expiryBytes[1];

        monthBytes[0] = expiryBytes[3];
        monthBytes[1] = expiryBytes[4];

        yearBytes[0] = expiryBytes[5];
        yearBytes[1] = expiryBytes[6];

        string memory day = string(dayBytes);
        string memory month = string(monthBytes);
        string memory year = string(yearBytes);

        string memory expiryDateString = string(
            abi.encodePacked(year, month, day)
        );

        uint256 expiryDateTimestamp = Formatter.dateToUnixTimestamp(
            expiryDateString
        );

        s_claimableTimestamp[msg.sender] = expiryDateTimestamp;
    }
}
