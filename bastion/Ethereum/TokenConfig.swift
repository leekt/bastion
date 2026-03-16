import Foundation

// MARK: - Token Identifier

/// Identifies a token for spending limit rules.
/// ETH and USDC have built-in support (no chain ID needed for identification).
/// Arbitrary ERC-20 tokens require an address and chain ID.
nonisolated enum TokenIdentifier: Codable, Hashable, Sendable {
    case eth
    case usdc
    case erc20(address: String, chainId: Int)

    var displayName: String {
        switch self {
        case .eth: return "ETH"
        case .usdc: return "USDC"
        case .erc20(let address, let chainId):
            let short = "\(address.prefix(6))...\(address.suffix(4))"
            return "ERC20(\(short)) on \(chainId)"
        }
    }

    /// Returns the token contract address for a given chain.
    /// ETH returns nil (native token). USDC returns the hardcoded address.
    func contractAddress(chainId: Int) -> String? {
        switch self {
        case .eth:
            return nil
        case .usdc:
            return USDCAddresses.address(for: chainId)
        case .erc20(let address, _):
            return address
        }
    }

    /// Number of decimals for display formatting.
    var decimals: Int {
        switch self {
        case .eth: return 18
        case .usdc: return 6
        case .erc20: return 18 // default, caller should override if known
        }
    }
}

// MARK: - USDC Addresses

/// Hardcoded USDC contract addresses per chain.
nonisolated enum USDCAddresses: Sendable {
    static let addresses: [Int: String] = [
        1:     "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // Ethereum Mainnet
        8453:  "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // Base
        42161: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", // Arbitrum One
        10:    "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", // Optimism
        137:   "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", // Polygon
    ]

    static func address(for chainId: Int) -> String? {
        addresses[chainId]
    }

    static var supportedChainIds: [Int] {
        Array(addresses.keys).sorted()
    }
}

// MARK: - Chain Config

nonisolated enum ChainConfig: Sendable {
    static let names: [Int: String] = [
        1:     "Ethereum",
        8453:  "Base",
        42161: "Arbitrum",
        10:    "Optimism",
        137:   "Polygon",
        11155111: "Sepolia",
        84532: "Base Sepolia",
    ]

    static func name(for chainId: Int) -> String {
        names[chainId] ?? "Chain \(chainId)"
    }
}
