1. [MEDIUM] [M-10] split() mints NFTs to msg.sender not the original owner
   Firm: Pashov Audit Group | Quality: 0/5
   Link: https://github.com/pashov/audits/blob/master/team/md/KittenSwap-security-review_2025-05-07.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/multisigs/GuardCM.sol::unpause
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/ServiceManager.sol::setOperatorWhitelist
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/ServiceManager.sol::changeImplementation

2. [MEDIUM] [M-02] Denial of Service via Large Payload Storage Exhaustion
   Firm: Shieldify | Quality: 0/5
   Link: https://github.com/shieldify-security/audits-portfolio-md/blob/main/Toki-Bridge-Security-Review.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/bridges/WormholeRelayerTimelock.sol::quoteEVMDeliveryPrice
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/bridges/WormholeRelayerTimelock.sol::sendPayloadToEvm
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/bridges/WormholeRelayerTimelock.sol::transferTokens

3. [LOW] Missing access control allows nonce manipulation
   Firm: TrailOfBits | Quality: 0/5
   Link: https://github.com/trailofbits/publications/blob/master/reviews/2025-08-gemini-smartwallet-securityreview.pdf
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/bridges/WormholeRelayerTimelock.sol::transferTokens
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/ServiceManager.sol::unbondWithSignature
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/ServiceManager.sol::registerAgentsWithSignature

4. [MEDIUM] Combination of Ownable and AccessControl can cause loss of admin functionality
   Firm: Cyfrin | Quality: 0/5
   Link: https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-09-25-cyfrin-button-basis-trade-v2.0.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/utils/ComplementaryServiceMetadata.sol::mapServices
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/utils/ComplementaryServiceMetadata.sol::ownerOf
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/utils/ComplementaryServiceMetadata.sol::baseURI

5. [MEDIUM] [M-02] Incorrect ticket price reference in JackpotBridgeManager causes user overpayment after price updates
   Firm: Code4rena | Quality: 0/5
   Link: https://code4rena.com/reports/2025-11-megapot
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/ServiceManagerProxy.sol::getImplementation
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerETH.sol::feeAmountTickSpacing
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerETH.sol::getPool

