"""
Multi-chain adapter.
Routes fetch requests to the correct chain's block explorer based on chain name.
"""

import logging
import os
from typing import Optional

from .evm_fetcher import EVMFetcher

logger = logging.getLogger(__name__)


# Default chain configurations (can be overridden via settings.yaml)
DEFAULT_CHAINS = {
    "ethereum": {
        "chain_id": 1,
        "explorer_api": "https://api.etherscan.io/api",
        "env_key": "ETHERSCAN_API_KEY",
        "rpc_url": "https://eth.llamarpc.com",
    },
    "bsc": {
        "chain_id": 56,
        "explorer_api": "https://api.bscscan.com/api",
        "env_key": "BSCSCAN_API_KEY",
        "rpc_url": "https://bsc-dataseed.binance.org",
    },
    "polygon": {
        "chain_id": 137,
        "explorer_api": "https://api.polygonscan.com/api",
        "env_key": "POLYGONSCAN_API_KEY",
        "rpc_url": "https://polygon-rpc.com",
    },
    "arbitrum": {
        "chain_id": 42161,
        "explorer_api": "https://api.arbiscan.io/api",
        "env_key": "ARBISCAN_API_KEY",
        "rpc_url": "https://arb1.arbitrum.io/rpc",
    },
    "optimism": {
        "chain_id": 10,
        "explorer_api": "https://api-optimistic.etherscan.io/api",
        "env_key": "OPTIMISM_API_KEY",
        "rpc_url": "https://mainnet.optimism.io",
    },
    "avalanche": {
        "chain_id": 43114,
        "explorer_api": "https://api.snowtrace.io/api",
        "env_key": "SNOWTRACE_API_KEY",
        "rpc_url": "https://api.avax.network/ext/bc/C/rpc",
    },
    "base": {
        "chain_id": 8453,
        "explorer_api": "https://api.basescan.org/api",
        "env_key": "BASESCAN_API_KEY",
        "rpc_url": "https://mainnet.base.org",
    },
}


class MultiChainFetcher:
    """
    Adapter that manages EVMFetcher instances for multiple chains.

    Usage:
        fetcher = MultiChainFetcher(chain_config)
        source, metadata = fetcher.fetch("0xAddress", chain="ethereum")
    """

    def __init__(self, chain_config: dict = None):
        """
        Args:
            chain_config: Override config from settings.yaml.
                         If None, uses DEFAULT_CHAINS with env vars for API keys.
        """
        self._chain_config = chain_config or DEFAULT_CHAINS
        self._fetchers: dict[str, EVMFetcher] = {}

    def _get_fetcher(self, chain: str) -> EVMFetcher:
        """Get or create an EVMFetcher for the specified chain."""
        chain = chain.lower().strip()

        if chain in self._fetchers:
            return self._fetchers[chain]

        if chain not in self._chain_config:
            raise ValueError(
                f"Unknown chain: '{chain}'. "
                f"Available chains: {', '.join(self._chain_config.keys())}"
            )

        cfg = self._chain_config[chain]
        explorer_api = cfg.get("explorer_api", "")
        rpc_url = cfg.get("rpc_url", "")

        # Resolve API key from env var name or direct value
        api_key = ""
        env_key = cfg.get("env_key", "")
        if env_key:
            api_key = os.environ.get(env_key, "")
        elif cfg.get("explorer_key"):
            # Direct key or env var reference like "${ETHERSCAN_API_KEY}"
            key_ref = cfg["explorer_key"]
            if key_ref.startswith("${") and key_ref.endswith("}"):
                env_name = key_ref[2:-1]
                api_key = os.environ.get(env_name, "")
            else:
                api_key = key_ref

        fetcher = EVMFetcher(
            explorer_api=explorer_api,
            api_key=api_key,
            rpc_url=rpc_url,
        )
        self._fetchers[chain] = fetcher
        return fetcher

    def fetch(self, address: str, chain: str = "ethereum") -> tuple[Optional[str], dict]:
        """
        Fetch contract source for the given chain.

        Args:
            address: Contract address.
            chain: Chain name (ethereum, bsc, polygon, arbitrum, optimism, avalanche, base).

        Returns:
            (source_code, metadata) — same as EVMFetcher.fetch()
        """
        try:
            fetcher = self._get_fetcher(chain)
        except ValueError as e:
            logger.error(str(e))
            return None, {"error": str(e)}

        logger.info(f"Fetching {address} from {chain}...")
        source, metadata = fetcher.fetch(address)
        metadata["chain"] = chain
        metadata["chain_id"] = self._chain_config.get(chain, {}).get("chain_id", 0)
        return source, metadata

    def fetch_bytecode(self, address: str, chain: str = "ethereum") -> Optional[str]:
        """Fetch deployed bytecode via RPC."""
        try:
            fetcher = self._get_fetcher(chain)
            return fetcher.fetch_bytecode(address)
        except ValueError as e:
            logger.error(str(e))
            return None

    def list_chains(self) -> list[str]:
        """Return list of supported chain names."""
        return list(self._chain_config.keys())

    def get_chain_info(self, chain: str) -> dict:
        """Return chain configuration info."""
        chain = chain.lower().strip()
        cfg = self._chain_config.get(chain, {})
        return {
            "name": chain,
            "chain_id": cfg.get("chain_id"),
            "explorer_api": cfg.get("explorer_api"),
            "rpc_url": cfg.get("rpc_url"),
            "has_api_key": bool(
                os.environ.get(cfg.get("env_key", ""), "")
            ),
        }
