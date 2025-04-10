import NetworkConfigInterface from "./NetworkConfigInterface";

/*  
 * Local Networks 
*/
export const hardhatLocal: NetworkConfigInterface = {
    chainId: 31337,
    symbol: "eth (test)",
    blockExplorer: {
        name: "Block explorer (not available for local chains)",
        generatorContractUrl: (contractAddress: string) => "#",
        generateTransactionUrl: (transactionAddress: string) => `#`,
    },
}

/*
 * Ethereum 
 */
export const ethereumTest: NetworkConfigInterface = {
    chainId: 11155111,
    symbol: " SepoliaETH",
    blockExplorer: {
      name: "Etherscan (Sepolia)",
      generatorContractUrl: (contracAddress: string) => `https://sepolia.etherscan.io//address/${contracAddress}`,
      generateTransactionUrl: (transactionAddress: string) => `https://sepolia.etherscan.io/tx/${transactionAddress}`,
    },
}

export const ethereumTestnet: NetworkConfigInterface = {
    chainId: 5,
    symbol: "ETH (test)",
    blockExplorer: {
      name: "Etherscan (Goerli)",
      generatorContractUrl: (contracAddress: string) => `https://goerli.etherscan.io/address/${contracAddress}`,
      generateTransactionUrl: (transactionAddress: string) => `https://goerli.etherscan.io/tx/${transactionAddress}`,
    },
}

export const ethereumMainnet: NetworkConfigInterface = {
    chainId: 1,
    symbol: "ETH",
    blockExplorer: {
        name: "Etherscan",
        generatorContractUrl: (contractAddress: string) => `https://etherscan.io/address/${contractAddress}`,
        generateTransactionUrl: (transactionAddress: string) => `https://etherscan.io/tx/${transactionAddress}`,
    },
}

/*
 * Polygon
 */
export const polygonTestnet: NetworkConfigInterface = {
    chainId: 80002,
    symbol: "MATIC (test)",
    blockExplorer: {
        name: "Polygonscan (Amoy)",
        generatorContractUrl: (contractAddress: string) => `https://amoy.polygonscan.com/address/${contractAddress}`,
        generateTransactionUrl: (transactionAddress: string) => `https://amoy.polygonscan.com/tx/${transactionAddress}`,
    },
}

export const polygonMainnet: NetworkConfigInterface = {
    chainId: 137,
    symbol: "MATIC",
    blockExplorer: {
        name: "Polygonscan",
        generatorContractUrl: (contractAddress: string) => `https://polygonscan.com/address/${contractAddress}`,
        generateTransactionUrl: (transactionAddress: string) => `https://polygonscan.com/tx/${transactionAddress}`,
    },
}

/*
 * Arbitrum
 */
export const arbitrumGoerli: NetworkConfigInterface = {
    chainId: 421613,
    symbol: "AGOR (test)",
    blockExplorer: {
        name: "Arbitrum Goerli",
        generatorContractUrl: (contractAddress: string) => `https://goerli-rollup-explorer.arbitrum.io/address/${contractAddress}`,
        generateTransactionUrl: (transactionAddress: string) => `https://goerli-rollup-explorer.arbitrum.io/tx/${transactionAddress}`,
    },
}

export const arbitrumOne: NetworkConfigInterface = {
    chainId: 42161,
    symbol: "ETH",
    blockExplorer: {
        name: "Arbitrum One",
        generatorContractUrl: (contractAddress: string) => `https://explorer.arbitrum.io/address/${contractAddress}`,
        generateTransactionUrl: (transactionAddress: string) => `https://explorer.arbitrum.io/tx/${transactionAddress}`,
    },
}

/*
 * Mandala
 */
export const niskala: NetworkConfigInterface = {
    chainId: 6025,
    symbol: "KPGT",
    blockExplorer: {
        name: "Mandala Niskala",
        generatorContractUrl: (contractAddress: string) => `https://niskala.mandalachain.io/address/${contractAddress}`,
        generateTransactionUrl: (transactionAddress: string) => `https://niskala.mandalachain.io/tx/${transactionAddress}`,
    },
}

export const devnet: NetworkConfigInterface = {
    chainId: 895670,
    symbol: "KPGD",
    blockExplorer: {
        name: "Mandala Devnet",
        generatorContractUrl: (contractAddress: string) => `https://nbs-explorer.mandalachain.io/address/${contractAddress}`,
        generateTransactionUrl: (transactionAddress: string) => `https://nbs-explorer.mandalachain.io/tx/${transactionAddress}`,
    },
}