"""
EVM contract source code fetcher.
Pulls verified contract source from block explorers (Etherscan, BscScan, etc.)
"""

import json
import logging
import os
import time
from typing import Optional
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)


class EVMFetcher:
    """
    Fetches verified Solidity source code from Etherscan-compatible block explorers.

    Usage:
        fetcher = EVMFetcher(explorer_api="https://api.etherscan.io/api", api_key="YOUR_KEY")
        source, metadata = fetcher.fetch("0xContractAddress")
    """

    # Rate limit: 5 requests/sec for free tier
    MIN_REQUEST_INTERVAL = 0.25

    def __init__(self, explorer_api: str, api_key: str = "", rpc_url: str = ""):
        self.explorer_api = explorer_api.rstrip("/")
        self.api_key = api_key
        self.rpc_url = rpc_url
        self._last_request_time = 0.0

    def fetch(self, address: str) -> tuple[Optional[str], dict]:
        """
        Fetch verified source code for a contract address.

        Args:
            address: Contract address (0x-prefixed hex string).

        Returns:
            (source_code, metadata_dict)
            source_code is None if fetch fails.
            metadata includes: contract_name, compiler_version, optimization, etc.
        """
        if not address.startswith("0x") or len(address) != 42:
            logger.error(f"Invalid address format: {address}")
            return None, {"error": "invalid_address"}

        self._rate_limit()

        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        }
        if self.api_key:
            params["apikey"] = self.api_key

        try:
            resp = requests.get(self.explorer_api, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if data.get("status") != "1" or data.get("message") != "OK":
                error_msg = data.get("result", "Unknown error")
                logger.warning(f"Explorer API error for {address}: {error_msg}")
                return None, {"error": str(error_msg)}

            results = data.get("result", [])
            if not results:
                logger.warning(f"No results for address {address}")
                return None, {"error": "no_results"}

            result = results[0]
            source_code = result.get("SourceCode", "")

            if not source_code:
                logger.warning(f"Contract at {address} is not verified or source not available")
                return None, {"error": "not_verified", "address": address}

            metadata = {
                "address": address,
                "contract_name": result.get("ContractName", "Unknown"),
                "compiler_version": result.get("CompilerVersion", ""),
                "optimization_used": result.get("OptimizationUsed", "") == "1",
                "runs": int(result.get("Runs", "0") or "0"),
                "evm_version": result.get("EVMVersion", "default"),
                "license_type": result.get("LicenseType", ""),
                "abi": result.get("ABI", ""),
                "proxy": result.get("Proxy", "0") == "1",
                "implementation": result.get("Implementation", ""),
            }

            # Handle multi-file source (JSON encoded)
            source_code = self._normalize_source(source_code, metadata)

            return source_code, metadata

        except requests.RequestException as e:
            logger.error(f"HTTP request failed: {e}")
            return None, {"error": str(e)}
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse explorer response: {e}")
            return None, {"error": str(e)}

    def fetch_bytecode(self, address: str) -> Optional[str]:
        """Fetch deployed bytecode via RPC (eth_getCode)."""
        if not self.rpc_url:
            logger.warning("No RPC URL configured, cannot fetch bytecode")
            return None

        self._rate_limit()
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getCode",
            "params": [address, "latest"],
            "id": 1,
        }
        try:
            resp = requests.post(self.rpc_url, json=payload, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            code = data.get("result", "0x")
            return code if code != "0x" else None
        except Exception as e:
            logger.error(f"Failed to fetch bytecode: {e}")
            return None

    def _normalize_source(self, source_code: str, metadata: dict) -> str:
        """
        Normalize source code from different explorer formats.
        Etherscan sometimes returns JSON-wrapped multi-file source.
        """
        # Check if source is double-JSON-encoded (Etherscan standard JSON)
        if source_code.startswith("{{"):
            # Strip outer braces
            try:
                inner = json.loads(source_code[1:-1])
                sources = inner.get("sources", {})
                if sources:
                    # Concatenate all source files
                    parts = []
                    for filename, content in sources.items():
                        parts.append(f"// ── {filename} ──────────────────────────────")
                        parts.append(content.get("content", ""))
                    source_code = "\n\n".join(parts)
                    metadata["multi_file"] = True
                    metadata["source_files"] = list(sources.keys())
            except json.JSONDecodeError:
                pass

        # Check if source is single JSON object with sources key
        elif source_code.startswith("{"):
            try:
                parsed = json.loads(source_code)
                if "sources" in parsed:
                    sources = parsed["sources"]
                    parts = []
                    for filename, content in sources.items():
                        parts.append(f"// ── {filename} ──────────────────────────────")
                        parts.append(content.get("content", str(content)))
                    source_code = "\n\n".join(parts)
                    metadata["multi_file"] = True
                    metadata["source_files"] = list(sources.keys())
            except json.JSONDecodeError:
                pass  # Use raw source as-is

        return source_code

    def _rate_limit(self):
        """Enforce rate limiting between API requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.MIN_REQUEST_INTERVAL:
            time.sleep(self.MIN_REQUEST_INTERVAL - elapsed)
        self._last_request_time = time.time()

    def save_source(self, source_code: str, output_path: str) -> str:
        """Save fetched source code to a file."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(source_code)
        logger.info(f"Saved source to: {output_path}")
        return output_path
