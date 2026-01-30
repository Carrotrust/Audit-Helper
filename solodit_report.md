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

6. [LOW] Inefficient Gas Price Derivation
   Firm: MixBytes | Quality: 0/5
   Link: https://github.com/mixbytes/audits_public/blob/master/DIA/Multi%20Scope/README.md#2-inefficient-gas-price-derivation
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/oracles/UniswapPriceOracle.sol::token0
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/oracles/UniswapPriceOracle.sol::getReserves
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/oracles/UniswapPriceOracle.sol::price0CumulativeLast

7. [HIGH] [H-05] Vulnerability in `PositionInteractionFacet` slippage control due to spot price
   Firm: Pashov Audit Group | Quality: 0/5
   Link: https://github.com/pashov/audits/blob/master/team/md/Hyperhyper-security-review_2025-03-30.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/BuyBackBurner.sol::_performSwap
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/BuyBackBurner.sol::_performSwap
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/BuyBackBurner.sol::getV3Pool

8. [HIGH] DELEGATECALL to staking precompile allows theft of all staked MON
   Firm: Spearbit | Quality: 0/5
   Link: https://github.com/spearbit/portfolio/blob/master/pdfs/Monad-Spearbit-Security-Review-September-2025.pdf
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/staking/StakingBase.sol::_transfer
   Match: /Users/mac/comp/2026-01-olas/autonolas-registries/contracts/staking/StakingBase.sol::_checkRatioPass
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/Tokenomics.sol::updateInflationPerSecondAndFractions

9. [MEDIUM] [M-12] No slippage protection during adding liquidity to uniswap
   Firm: Code4rena | Quality: 0/5
   Link: https://code4rena.com/reports/2025-04-virtuals-protocol
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerCore.sol::_decreaseLiquidity
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerETH.sol::_checkTokensAndRemoveLiquidityV2
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerOptimism.sol::_checkTokensAndRemoveLiquidityV2

10. [MEDIUM] [M-01] Bridge messages can be permanently lost
   Firm: Pashov Audit Group | Quality: 0/5
   Link: https://github.com/pashov/audits/blob/master/team/md/Nucleus-security-review_2024-12-14.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/staking/DefaultTargetDispenserL2.sol::balanceOf
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/staking/DefaultTargetDispenserL2.sol::approve
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/staking/DefaultTargetDispenserL2.sol::transfer

11. [MEDIUM] [M-02] Reentrancy lock hinders reward distribution
   Firm: Pashov Audit Group | Quality: 0/5
   Link: https://github.com/pashov/audits/blob/master/team/md/Hyperstable-security-review_2025-06-03.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/bridges/OptimismMessenger.sol::changeSourceGovernor
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/bridges/WormholeMessenger.sol::changeSourceGovernor

12. [MEDIUM] `OracleUniGeoDistribution` oracle tick validation is flawed
   Firm: Cyfrin | Quality: 0/5
   Link: https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-06-10-cyfrin-bunni-v2.1.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerCore.sol::optimizeLiquidityAmounts
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerCore.sol::getTwapFromOracle

13. [MEDIUM] M-17: `Maker.adjustMaker` always reverts when trying to reduce maker liquidity while current price is below position range
   Firm: Sherlock | Quality: 0/5
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerCore.sol::convertToV3
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerCore.sol::changeRanges

14. [LOW] Burn and bridge mechanism can be delayed due to paused token bridge state
   Firm: Cyfrin | Quality: 0/5
   Link: https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-11-03-cyfrin-linea-burn-v2.2.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/pol/LiquidityManagerOptimism.sol::_burn
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/BuyBackBurner.sol::transfer

15. [MEDIUM] Attempts to Bridge WETH Using ZkStack_CustomGasToken_Adapter Will Fail
   Firm: OpenZeppelin | Quality: 0/5
   Link: https://blog.openzeppelin.com/across-audit
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/Bridge2BurnerGnosis.sol::relayTokens
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/BuyBackBurnerUniswap.sol::swapExactTokensForTokens

16. [MEDIUM] M-2: ETH Address Approval Attempt Causes All Zeta Swaps to Revert
   Firm: Sherlock | Quality: 0/5
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/Bridge2BurnerOptimism.sol::approve
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/BuyBackBurnerUniswap.sol::approve

17. [HIGH] Arithmetic Overflow in `getPrice` When Feeds Return Large Values
   Firm: MixBytes | Quality: 0/5
   Link: https://github.com/mixbytes/audits_public/blob/master/NUTS%20Finance/Pike/README.md#1-arithmetic-overflow-in-getprice-when-feeds-return-large-values
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/BuyBackBurner.sol::checkPoolAndGetCenterPrice
   Match: /Users/mac/comp/2026-01-olas/autonolas-tokenomics/contracts/utils/BuyBackBurner.sol::factoryV3

18. [MEDIUM] [M-17] `VirtualGenesisDAO.sol:earlyExecute()` proposals can be executed two times
   Firm: Code4rena | Quality: 0/5
   Link: https://code4rena.com/reports/2025-04-virtuals-protocol
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/GovernorOLAS.sol::_execute

19. [MEDIUM] Missing `change_funding_rate` Call After Price Update in `perp_mass_cancel` and `perp_order_cancel`
   Firm: Cyfrin | Quality: 0/5
   Link: https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-15-cyfrin-deriverse-dex-v2.0.md
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/GovernorOLAS.sol::_cancel

20. [MEDIUM] `TimelockSafeGuard.cancel` Not Whitelisted for Immediate Execution
   Firm: MixBytes | Quality: 0/5
   Link: https://github.com/mixbytes/audits_public/blob/master/Mantle%20Network/FBTC%20Timelock/README.md#1-timelocksafeguardcancel-not-whitelisted-for-immediate-execution
   Match: /Users/mac/comp/2026-01-olas/autonolas-governance/contracts/utils/GovernorTimelockControl.sol::_cancel

