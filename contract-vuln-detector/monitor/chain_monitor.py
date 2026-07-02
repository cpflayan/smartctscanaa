"""
On-chain contract monitoring.
Supports periodic re-scanning, event listening, transaction monitoring,
and new contract deployment detection.
"""

import hashlib
import logging
import threading
import time
from typing import Optional

import click

from fetchers.multi_chain import MultiChainFetcher
from monitor.notifier import Notifier
from scanners.base_scanner import Finding

logger = logging.getLogger(__name__)


class ChainMonitor:
    """
    Monitors on-chain contracts for changes, events, transactions,
    and new deployments.

    Usage:
        monitor = ChainMonitor(config, chain_config, notifier, scan_fn)
        monitor.watch_address("0x...", chain="polygon", modes=["rescan", "events", "tx"])
        monitor.watch_deployments(chain="polygon")
        monitor.start()
        # ... later ...
        monitor.stop()
    """

    def __init__(
        self,
        config: dict,
        chain_config: dict,
        notifier: Notifier,
        scan_fn=None,
    ):
        """
        Args:
            config: Full config dict (includes monitor section).
            chain_config: Chain configuration from settings.yaml.
            notifier: Notifier instance for alerts.
            scan_fn: Callable(source_code, file_path, config) -> list[Finding].
                     If None, uses a default that runs pattern scanner only.
        """
        self.config = config
        self.chain_config = chain_config
        self.notifier = notifier
        self.scan_fn = scan_fn or self._default_scan

        monitor_cfg = config.get("monitor", {})
        self.rescan_interval = monitor_cfg.get("interval", 300)
        self.poll_interval = monitor_cfg.get("poll_interval", 12)

        self.fetcher = MultiChainFetcher(chain_config)
        self._web3_cache: dict[str, Web3] = {}

        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()

        self._source_hashes: dict[str, str] = {}
        self._last_block: dict[str, int] = {}

        self._watched: list[dict] = []
        self._deploy_chains: list[str] = []

    def _get_web3(self, chain: str) -> Optional[object]:
        """Get or create a Web3 instance for the given chain."""
        if chain in self._web3_cache:
            return self._web3_cache[chain]

        cfg = self.chain_config.get(chain, {})
        rpc_url = cfg.get("rpc_url", "")
        if not rpc_url:
            logger.warning(f"No RPC URL configured for chain: {chain}")
            return None

        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 15}))
            self._web3_cache[chain] = w3
            return w3
        except Exception as e:
            logger.error(f"Failed to connect to {chain} RPC: {e}")
            return None

    def watch_address(self, address: str, chain: str = "ethereum", modes: list[str] = None):
        """
        Register an address to monitor.

        Args:
            address: Contract address (0x...).
            chain: Chain name.
            modes: List of modes: "rescan", "events", "tx".
        """
        if modes is None:
            modes = ["rescan", "events", "tx"]

        self._watched.append({
            "address": address.lower(),
            "chain": chain,
            "modes": modes,
        })

    def watch_deployments(self, chain: str = "ethereum"):
        """Register a chain to monitor for new contract deployments."""
        if chain not in self._deploy_chains:
            self._deploy_chains.append(chain)

    def start(self):
        """Start all monitoring threads."""
        self._stop_event.clear()

        for entry in self._watched:
            addr = entry["address"]
            chain = entry["chain"]
            modes = entry["modes"]

            if "rescan" in modes:
                t = threading.Thread(
                    target=self._periodic_rescan_loop,
                    args=(addr, chain),
                    daemon=True,
                    name=f"rescan-{chain}-{addr[:8]}",
                )
                self._threads.append(t)

            if "events" in modes:
                t = threading.Thread(
                    target=self._event_listener_loop,
                    args=(addr, chain),
                    daemon=True,
                    name=f"events-{chain}-{addr[:8]}",
                )
                self._threads.append(t)

            if "tx" in modes:
                t = threading.Thread(
                    target=self._tx_monitor_loop,
                    args=(addr, chain),
                    daemon=True,
                    name=f"tx-{chain}-{addr[:8]}",
                )
                self._threads.append(t)

        for chain in self._deploy_chains:
            t = threading.Thread(
                target=self._deploy_monitor_loop,
                args=(chain,),
                daemon=True,
                name=f"deploy-{chain}",
            )
            self._threads.append(t)

        for t in self._threads:
            t.start()

        click.echo(click.style(
            f"Monitor started: {len(self._threads)} thread(s) running",
            fg="green", bold=True,
        ))

    def stop(self):
        """Stop all monitoring threads."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
        click.echo("Monitor stopped.")

    def wait(self):
        """Block until stop() is called or KeyboardInterrupt."""
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=1)
        except KeyboardInterrupt:
            self.stop()

    # ─── Periodic Re-scan ─────────────────────────────────────────────────────

    def _periodic_rescan_loop(self, address: str, chain: str):
        """Periodically fetch source code and re-scan if changed."""
        click.echo(f"  [rescan] Watching {address} on {chain} (every {self.rescan_interval}s)")

        while not self._stop_event.is_set():
            try:
                source, metadata = self.fetcher.fetch(address, chain=chain)
                if source is None:
                    logger.debug(f"Rescan: failed to fetch {address}")
                else:
                    source_hash = hashlib.sha256(source.encode()).hexdigest()
                    key = f"{chain}:{address}"
                    prev_hash = self._source_hashes.get(key)

                    if prev_hash is None:
                        self._source_hashes[key] = source_hash
                        self.notifier.notify(
                            "source_changed",
                            f"Initial scan: {address} on {chain} ({metadata.get('contract_name', '?')})",
                            contract_info=metadata,
                        )
                        self._run_scan(source, address, metadata)
                    elif source_hash != prev_hash:
                        self._source_hashes[key] = source_hash
                        self.notifier.notify(
                            "source_changed",
                            f"Source changed: {address} on {chain} ({metadata.get('contract_name', '?')})",
                            contract_info=metadata,
                        )
                        self._run_scan(source, address, metadata)
                    else:
                        logger.debug(f"Rescan: no change for {address}")

            except Exception as e:
                logger.warning(f"Rescan error for {address}: {e}")

            self._stop_event.wait(timeout=self.rescan_interval)

    # ─── Event Listener ───────────────────────────────────────────────────────

    def _event_listener_loop(self, address: str, chain: str):
        """Poll for contract event logs via eth_getLogs."""
        w3 = self._get_web3(chain)
        if not w3:
            return

        from web3 import Web3

        click.echo(f"  [events] Listening events: {address} on {chain}")

        try:
            last_block = w3.eth.block_number
        except Exception as e:
            logger.error(f"Cannot get initial block for {chain}: {e}")
            return

        while not self._stop_event.is_set():
            try:
                current_block = w3.eth.block_number
                if current_block <= last_block:
                    self._stop_event.wait(timeout=self.poll_interval)
                    continue

                from_block = last_block + 1
                logs = w3.eth.get_logs({
                    "address": Web3.to_checksum_address(address),
                    "fromBlock": from_block,
                    "toBlock": current_block,
                })

                for log_entry in logs:
                    tx_hash = log_entry.get("transactionHash", b"").hex()
                    block_num = log_entry.get("blockNumber", "?")
                    topics = log_entry.get("topics", [])
                    topic0 = topics[0].hex() if topics else "unknown"

                    self.notifier.notify(
                        "new_event",
                        f"{chain}:{address} | block={block_num} tx={tx_hash[:16]}... topic0={topic0[:16]}...",
                        severity="info",
                    )

                last_block = current_block

            except Exception as e:
                logger.warning(f"Event listener error for {address} on {chain}: {e}")

            self._stop_event.wait(timeout=self.poll_interval)

    # ─── Transaction Monitor ──────────────────────────────────────────────────

    def _tx_monitor_loop(self, address: str, chain: str):
        """Monitor new blocks for transactions targeting the address."""
        w3 = self._get_web3(chain)
        if not w3:
            return

        from web3 import Web3

        click.echo(f"  [tx] Monitoring tx: {address} on {chain}")

        try:
            last_block = w3.eth.block_number
        except Exception as e:
            logger.error(f"Cannot get initial block for {chain}: {e}")
            return

        checksum_addr = Web3.to_checksum_address(address)

        while not self._stop_event.is_set():
            try:
                current_block = w3.eth.block_number
                if current_block <= last_block:
                    self._stop_event.wait(timeout=self.poll_interval)
                    continue

                for block_num in range(last_block + 1, current_block + 1):
                    try:
                        block = w3.eth.get_block(block_num, full_transactions=True)
                    except Exception:
                        continue

                    for tx in block.get("transactions", []):
                        tx_to = tx.get("to")
                        if tx_to and tx_to.lower() == checksum_addr.lower():
                            tx_hash = tx.get("hash", b"").hex()
                            tx_from = tx.get("from", "?")
                            value = tx.get("value", 0)

                            self.notifier.notify(
                                "suspicious_tx",
                                f"{chain}:{address} | block={block_num} from={tx_from} value={value} tx={tx_hash[:16]}...",
                                severity="medium",
                            )

                last_block = current_block

            except Exception as e:
                logger.warning(f"TX monitor error for {address} on {chain}: {e}")

            self._stop_event.wait(timeout=self.poll_interval)

    # ─── Deployment Monitor ───────────────────────────────────────────────────

    def _deploy_monitor_loop(self, chain: str):
        """Monitor new blocks for contract creation transactions (to=null)."""
        w3 = self._get_web3(chain)
        if not w3:
            return

        click.echo(f"  [deploy] Monitoring new deployments on {chain}")

        try:
            last_block = w3.eth.block_number
        except Exception as e:
            logger.error(f"Cannot get initial block for {chain}: {e}")
            return

        while not self._stop_event.is_set():
            try:
                current_block = w3.eth.block_number
                if current_block <= last_block:
                    self._stop_event.wait(timeout=self.poll_interval)
                    continue

                for block_num in range(last_block + 1, current_block + 1):
                    try:
                        block = w3.eth.get_block(block_num, full_transactions=True)
                    except Exception:
                        continue

                    for tx in block.get("transactions", []):
                        if tx.get("to") is None:
                            tx_hash = tx.get("hash", b"").hex()
                            tx_from = tx.get("from", "?")

                            self.notifier.notify(
                                "new_contract",
                                f"New contract on {chain} | block={block_num} deployer={tx_from} tx={tx_hash[:16]}...",
                                severity="medium",
                            )

                            self._try_scan_new_contract(tx, chain, block_num)

                last_block = current_block

            except Exception as e:
                logger.warning(f"Deploy monitor error on {chain}: {e}")

            self._stop_event.wait(timeout=self.poll_interval)

    def _try_scan_new_contract(self, tx: dict, chain: str, block_num: int):
        """Try to fetch and scan a newly deployed contract."""
        try:
            receipt = self._web3_cache[chain].eth.get_transaction_receipt(
                tx.get("hash", b"")
            )
            contract_address = receipt.get("contractAddress")
            if not contract_address:
                return

            source, metadata = self.fetcher.fetch(contract_address, chain=chain)
            if source:
                metadata["block_number"] = block_num
                self._run_scan(source, contract_address, metadata)
        except Exception as e:
            logger.debug(f"Cannot scan new contract: {e}")

    # ─── Scan Helper ──────────────────────────────────────────────────────────

    def _run_scan(self, source_code: str, address: str, metadata: dict):
        """Run scanners on source code and notify with findings."""
        try:
            findings = self.scan_fn(source_code, address, self.config)
            if findings:
                max_sev = max((f.severity for f in findings), key=lambda s: s.value)
                self.notifier.notify(
                    "scan_complete",
                    f"Scan complete: {address} ({metadata.get('contract_name', '?')}) - {len(findings)} finding(s)",
                    findings=findings,
                    contract_info=metadata,
                    severity=max_sev.value,
                )
            else:
                self.notifier.notify(
                    "scan_complete",
                    f"Scan complete: {address} - no issues found",
                    contract_info=metadata,
                    severity="info",
                )
        except Exception as e:
            logger.warning(f"Scan failed for {address}: {e}")

    @staticmethod
    def _default_scan(source_code: str, file_path: str, config: dict) -> list[Finding]:
        """Default scan function using pattern scanner only."""
        from scanners.pattern_scanner import PatternScanner
        scanner = PatternScanner(config.get("scanners", {}).get("pattern", {}))
        return scanner.scan(source_code, file_path)
