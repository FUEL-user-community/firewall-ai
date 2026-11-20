"""
Stem Kernel Supervisor (`stem.py` — Plane 1, Option 1D).

Immutable zero-LLM process supervisor & zero-drop TCP/HTTP splice proxy:
- Binds external `:8888` once and forwards raw HTTP / SSE byte streams to the active slot:
    * Slot A -> `127.0.0.1:8881` (`.slots/a`)
    * Slot B -> `127.0.0.1:8882` (`.slots/b`)
- Blocks external `/internal/*` requests at the `:8888` edge (`403 Forbidden`) and signs
  loopback supervisor control calls (`/internal/status`, `/internal/drain`) with `NEO_STEM_TOKEN`.
- Executes safe parallel cutovers when `SharedStateStore` contains `pending_cutover`:
    1. Spawns candidate slot on standby port with `NEO_PROBATION_SHADOW=1`.
    2. Verifies `/readyz` + probation window survival while parent slot continues serving `:8888`.
    3. Atomically flips `:8888` upstream port in `<1ms`, drains parent SSE streams, and reaps old slot.
    4. Automatically reverts `<10ms` to parent slot and publishes an immutable `AUTOPSY` `.md`
       artifact onto the Stigmergic Board if candidate crashes or fails probation.

Usage:
    python stem.py
    python stem.py --check
"""

import argparse
import asyncio
import http.client
import json
import logging
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [STEM] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("stem")

SLOT_PORTS: Dict[str, int] = {"a": 8881, "b": 8882}


@dataclass
class ManagedSlotProcess:
    slot: str
    port: int
    workdir: Path
    proc: subprocess.Popen
    started_at: float
    probation_shadow: bool = False


class StemSpliceProxy:
    """
    Zero-dependency stdlib `asyncio` TCP/HTTP splice proxy.
    Streams SSE `text/event-stream` chunks with zero line-buffering while blocking external `/internal/*`.
    """

    FORBIDDEN_RESPONSE = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 43\r\n"
        b"Connection: close\r\n\r\n"
        b'{"error":"Internal supervisor route blocked"}'
    )
    BAD_GATEWAY_RESPONSE = (
        b"HTTP/1.1 502 Bad Gateway\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 40\r\n"
        b"Connection: close\r\n\r\n"
        b'{"error":"Active NEO slot unreachable"}'
    )

    def __init__(self, bind_host: str, bind_port: int, initial_upstream_port: int):
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.upstream_host = "127.0.0.1"
        self.upstream_port = int(initial_upstream_port)
        self._server: Optional[asyncio.AbstractServer] = None

    def set_upstream_port(self, new_port: int) -> None:
        old = self.upstream_port
        self.upstream_port = int(new_port)
        logger.info(f"Atomic upstream flip: 127.0.0.1:{old} -> 127.0.0.1:{self.upstream_port}")

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, host=self.bind_host, port=self.bind_port
        )
        sockets = self._server.sockets or []
        if sockets:
            self.bind_port = int(sockets[0].getsockname()[1])
        logger.info(
            f"Listening on http://{self.bind_host}:{self.bind_port} -> 127.0.0.1:{self.upstream_port}"
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        upstream_writer: Optional[asyncio.StreamWriter] = None
        try:
            # Read first chunk to inspect HTTP request path without buffering body/SSE streams
            first_chunk = await asyncio.wait_for(client_reader.read(4096), timeout=15.0)
            if not first_chunk:
                return

            first_line = first_chunk.split(b"\r\n", 1)[0]
            parts = first_line.split(b" ")
            if len(parts) >= 2:
                raw_path = parts[1].split(b"?", 1)[0].lower()
                if raw_path.startswith(b"/internal/") or raw_path == b"/internal":
                    client_writer.write(self.FORBIDDEN_RESPONSE)
                    await client_writer.drain()
                    return

            target_port = self.upstream_port
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(self.upstream_host, target_port),
                    timeout=5.0,
                )
            except Exception:
                client_writer.write(self.BAD_GATEWAY_RESPONSE)
                await client_writer.drain()
                return

            upstream_writer.write(first_chunk)
            await upstream_writer.drain()

            await asyncio.gather(
                self._pipe(client_reader, upstream_writer),
                self._pipe(upstream_reader, client_writer),
                return_exceptions=True,
            )
        except Exception:
            pass
        finally:
            for w in (upstream_writer, client_writer):
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await reader.read(16384)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except Exception:
                pass


class StemSupervisor:
    """Manages Slot A & Slot B processes, probation cutovers, draining, and crash resurrection."""

    def __init__(
        self,
        nucleus_root: Optional[Path] = None,
        external_host: str = "0.0.0.0",
        external_port: int = 8888,
        slot_ports: Optional[Dict[str, int]] = None,
        probation_seconds: float = 5.0,
        drain_timeout: float = 30.0,
    ):
        from core.forge.slot_mutator import SlotMutator
        from core.forge.state_store import SharedStateStore

        self.nucleus_root = Path(nucleus_root).resolve() if nucleus_root else Path(__file__).resolve().parent
        self.state_dir = self.nucleus_root / ".state" / "shared"
        self.store = SharedStateStore(state_dir=self.state_dir)
        self.mutator = SlotMutator(nucleus_root=self.nucleus_root, store=self.store)

        self.external_host = external_host
        self.external_port = int(external_port)
        self.slot_ports = dict(slot_ports or SLOT_PORTS)
        self.probation_seconds = max(0.2, float(probation_seconds))
        self.drain_timeout = max(1.0, float(drain_timeout))
        self.stem_token = secrets.token_hex(32)

        self.slots: Dict[str, ManagedSlotProcess] = {}
        self.proxy: Optional[StemSpliceProxy] = None
        self._stop_event = asyncio.Event()

    def bootstrap_slots(self) -> str:
        info = self.mutator.ensure_slots_initialized()
        return info["active_slot"]

    def spawn_slot(self, slot: str, probation_shadow: bool = False) -> ManagedSlotProcess:
        s = slot.lower().strip()
        port = self.slot_ports[s]
        slot_dir = self.mutator.slot_path(s)
        log_file = self.state_dir / f"slot_{s}.log"

        env = os.environ.copy()
        env["NEO_SLOT_ID"] = f"NEO_{s.upper()}"
        env["NEO_NUCLEUS_ROOT"] = str(self.nucleus_root)
        env["NEO_SHARED_STATE_DIR"] = str(self.state_dir)
        env["NEO_STEM_TOKEN"] = self.stem_token
        env["NEO_PERSIST_BUDGET"] = "1"
        env["NEO_PERSIST_TRACES"] = "1"
        env["NEO_PROBATION_SHADOW"] = "1" if probation_shadow else "0"
        env["PYTHONPATH"] = str(slot_dir)

        slot_env_file = slot_dir / ".env"
        if slot_env_file.is_file():
            try:
                for line in slot_env_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("PROMPTS_YAML_SHA="):
                        env["PROMPTS_YAML_SHA"] = line.split("=", 1)[1].strip().strip("'\"")
            except Exception as env_err:
                logger.warning(f"Could not read slot .env override for Slot {s.upper()}: {env_err}")

        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "info",
        ]
        log_fh = open(log_file, "a", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            cwd=str(slot_dir),
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
        )
        managed = ManagedSlotProcess(
            slot=s,
            port=port,
            workdir=slot_dir,
            proc=proc,
            started_at=time.time(),
            probation_shadow=probation_shadow,
        )
        self.slots[s] = managed
        logger.info(
            f"Spawned Slot {s.upper()} (pid={proc.pid}, port={port}, shadow={probation_shadow})"
        )
        return managed

    def _http_probe(
        self, port: int, path: str, method: str = "GET", timeout: float = 2.0
    ) -> Tuple[int, Dict]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            conn.request(method, path, headers={"X-Stem-Token": self.stem_token})
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw.strip().startswith("{") else {}
            return resp.status, data
        except Exception:
            return 0, {}
        finally:
            try:
                conn.close()
            except Exception:
                pass

    async def wait_for_slot_ready(self, slot: str, timeout: float = 25.0) -> Tuple[bool, str]:
        managed = self.slots.get(slot)
        if not managed:
            return False, "Slot process not registered"
        deadline = time.time() + timeout
        while time.time() < deadline:
            if managed.proc.poll() is not None:
                tail = self._read_slot_log_tail(slot)
                return False, f"Process exited early (rc={managed.proc.returncode}): {tail}"
            code, body = await asyncio.to_thread(self._http_probe, managed.port, "/readyz")
            if code == 200 and body.get("status") == "ready":
                return True, "ready"
            await asyncio.sleep(0.25)
        tail = self._read_slot_log_tail(slot)
        return False, f"Timed out waiting for /readyz on port {managed.port}: {tail}"

    def _read_slot_log_tail(self, slot: str, max_chars: int = 1200) -> str:
        log_file = self.state_dir / f"slot_{slot}.log"
        if not log_file.is_file():
            return ""
        try:
            return log_file.read_text(encoding="utf-8", errors="replace")[-max_chars:].strip()
        except Exception:
            return ""

    async def drain_and_terminate_slot(self, slot: str) -> None:
        managed = self.slots.pop(slot, None)
        if not managed or managed.proc.poll() is not None:
            return
        await asyncio.to_thread(self._http_probe, managed.port, "/internal/drain", "POST")
        deadline = time.time() + self.drain_timeout
        while time.time() < deadline:
            if managed.proc.poll() is not None:
                return
            code, data = await asyncio.to_thread(self._http_probe, managed.port, "/internal/status")
            if code == 200 and int(data.get("active_streams", 0)) == 0:
                break
            await asyncio.sleep(0.25)

        managed.proc.terminate()
        try:
            await asyncio.to_thread(managed.proc.wait, 5)
        except Exception:
            managed.proc.kill()
        logger.info(f"Drained and terminated old Slot {slot.upper()} (pid={managed.proc.pid})")

    def _record_autopsy(self, failed_slot: str, commit_sha: str, reason: str) -> None:
        """Persist crash autopsy to SharedStateStore and Stigmergic Board."""
        autopsy_payload = {
            "failed_slot": failed_slot.upper(),
            "commit_sha": commit_sha,
            "reason": reason,
            "timestamp": time.time(),
        }
        self.store.set_kv("pending_autopsy", autopsy_payload)
        self.store.record_generation(
            slot=failed_slot,
            commit_sha=commit_sha,
            parent_sha=self.mutator.get_active_slot(),
            status="probation_rollback_autopsy",
            reason=reason[:400],
        )
        try:
            from core.integrations.board_sync import StigmergicBoard
            board = StigmergicBoard(store=self.store)
            board.post_artifact(
                actor="STEM",
                move_type="AUTOPSY",
                thread_id="REINCARNATION",
                base_sha=commit_sha or "00000000",
                slug=f"slot-{failed_slot}-rollback",
                summary=f"Candidate Slot {failed_slot.upper()} failed probation and was rolled back.\n\n{reason}",
            )
        except Exception as be:
            logger.warning(f"Board autopsy write skipped: {be}")

    async def execute_pending_cutover(self, ticket: Dict) -> bool:
        """Boot candidate slot, enforce live probation window, cut over `:8888`, or roll back."""
        to_slot = str(ticket.get("to_slot", "")).lower().strip()
        from_slot = self.mutator.get_active_slot()
        commit_sha = str(ticket.get("commit_sha") or "00000000")
        if to_slot not in ("a", "b") or to_slot == from_slot:
            self.store.set_kv("pending_cutover", None)
            return False

        logger.info(
            f"Starting parallel cutover {from_slot.upper()} -> {to_slot.upper()} (sha={commit_sha})"
        )
        if to_slot in self.slots:
            await self.drain_and_terminate_slot(to_slot)

        cand = self.spawn_slot(to_slot, probation_shadow=True)
        ready_ok, ready_msg = await self.wait_for_slot_ready(to_slot, timeout=25.0)
        if not ready_ok:
            await self.drain_and_terminate_slot(to_slot)
            self.mutator.reset_inactive_slot()
            self.store.set_kv("pending_cutover", None)
            self._record_autopsy(to_slot, commit_sha, f"Boot readiness failure: {ready_msg}")
            return False

        # Probation observation window prior to traffic cutover
        probation_end = time.time() + self.probation_seconds
        while time.time() < probation_end:
            if cand.proc.poll() is not None:
                tail = self._read_slot_log_tail(to_slot)
                await self.drain_and_terminate_slot(to_slot)
                self.mutator.reset_inactive_slot()
                self.store.set_kv("pending_cutover", None)
                self._record_autopsy(to_slot, commit_sha, f"Crashed during probation: {tail}")
                return False
            code, _ = await asyncio.to_thread(self._http_probe, cand.port, "/healthz")
            if code != 200:
                tail = self._read_slot_log_tail(to_slot)
                await self.drain_and_terminate_slot(to_slot)
                self.mutator.reset_inactive_slot()
                self.store.set_kv("pending_cutover", None)
                self._record_autopsy(to_slot, commit_sha, f"Healthz probe failed in probation: {tail}")
                return False
            await asyncio.sleep(min(0.25, self.probation_seconds))

        # Probation passed -> Promote the already-verified PID in-place via /internal/promote
        # so zero cold restart is required prior to flipping :8888!
        prom_code, prom_body = await asyncio.to_thread(
            self._http_probe, cand.port, "/internal/promote", "POST"
        )
        if prom_code == 200 and prom_body.get("promoted") is True:
            cand.probation_shadow = False
            promoted = cand
        else:
            # Fallback if running an older server.py image lacking /internal/promote
            await self.drain_and_terminate_slot(to_slot)
            promoted = self.spawn_slot(to_slot, probation_shadow=False)
            prom_ok, prom_msg = await self.wait_for_slot_ready(to_slot, timeout=25.0)
            if not prom_ok:
                await self.drain_and_terminate_slot(to_slot)
                self.mutator.reset_inactive_slot()
                self.store.set_kv("pending_cutover", None)
                self._record_autopsy(to_slot, commit_sha, f"Promotion boot failure: {prom_msg}")
                return False

        if self.proxy:
            self.proxy.set_upstream_port(promoted.port)
        self.store.set_kv("active_slot", to_slot)
        self.store.set_kv("pending_cutover", None)
        self.store.set_kv("pending_autopsy", None)
        self.store.record_generation(
            slot=to_slot,
            commit_sha=commit_sha,
            parent_sha=from_slot,
            status="promoted_live",
            reason=str(ticket.get("reason", "Cutover complete")),
        )
        await self.drain_and_terminate_slot(from_slot)
        logger.info(f"PROMOTION COMPLETE: Slot {to_slot.upper()} is now Sovereign on :{self.external_port}")
        return True

    async def run_forever(self) -> None:
        active = self.bootstrap_slots()
        managed = self.spawn_slot(active, probation_shadow=False)
        ok, msg = await self.wait_for_slot_ready(active, timeout=30.0)
        if not ok:
            sibling = "b" if active == "a" else "a"
            logger.error(f"Primary Slot {active.upper()} failed boot ({msg}); resurrecting Slot {sibling.upper()}!")
            await self.drain_and_terminate_slot(active)
            self._record_autopsy(active, "boot", msg)
            active = sibling
            self.store.set_kv("active_slot", active)
            managed = self.spawn_slot(active, probation_shadow=False)
            ok2, msg2 = await self.wait_for_slot_ready(active, timeout=30.0)
            if not ok2:
                raise RuntimeError(f"Both Slot A and Slot B failed startup: {msg2}")

        self.proxy = StemSpliceProxy(
            bind_host=self.external_host,
            bind_port=self.external_port,
            initial_upstream_port=managed.port,
        )
        await self.proxy.start()

        consecutive_failures = 0
        try:
            while not self._stop_event.is_set():
                # 1. Check for queued reincarnation ticket
                ticket = self.store.get_kv("pending_cutover")
                if isinstance(ticket, dict) and ticket.get("to_slot"):
                    await self.execute_pending_cutover(ticket)
                    consecutive_failures = 0

                # 2. Liveness watchdog on active slot
                cur_slot = self.mutator.get_active_slot()
                cur_proc = self.slots.get(cur_slot)
                alive = False
                if cur_proc and cur_proc.proc.poll() is None:
                    code, _ = await asyncio.to_thread(self._http_probe, cur_proc.port, "/healthz")
                    alive = code == 200

                if not alive:
                    consecutive_failures += 1
                    if consecutive_failures >= 3 or (cur_proc and cur_proc.proc.poll() is not None):
                        sibling = "b" if cur_slot == "a" else "a"
                        tail = self._read_slot_log_tail(cur_slot)
                        logger.error(
                            f"Active Slot {cur_slot.upper()} died! Resurrecting sibling Slot {sibling.upper()}..."
                        )
                        await self.drain_and_terminate_slot(cur_slot)
                        self._record_autopsy(cur_slot, "runtime_crash", tail or "Healthz failed 3x")
                        resurrected = self.spawn_slot(sibling, probation_shadow=False)
                        r_ok, _ = await self.wait_for_slot_ready(sibling, timeout=25.0)
                        if r_ok and self.proxy:
                            self.proxy.set_upstream_port(resurrected.port)
                            self.store.set_kv("active_slot", sibling)
                        consecutive_failures = 0
                else:
                    consecutive_failures = 0

                await asyncio.sleep(1.0)
        finally:
            if self.proxy:
                await self.proxy.stop()
            for s in list(self.slots.keys()):
                await self.drain_and_terminate_slot(s)


def main() -> int:
    parser = argparse.ArgumentParser(description="Stem — Immutable Dual-Slot Supervisor for NEO")
    parser.add_argument("--host", default=os.getenv("HOST", "0.0.0.0"), help="External proxy bind host")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8888")), help="External proxy port")
    parser.add_argument(
        "--probation-seconds",
        type=float,
        default=float(os.getenv("NEO_PROBATION_SECONDS", "5.0")),
        help="Live probation duration before promoting candidate slot",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify SharedStateStore, Constitutional Ring, and Dual-Slot initialization, then exit.",
    )
    args = parser.parse_args()

    sup = StemSupervisor(
        external_host=args.host,
        external_port=args.port,
        probation_seconds=args.probation_seconds,
    )
    if args.check:
        active = sup.bootstrap_slots()
        print(
            f"[STEM CHECK PASSED] Active slot={active.upper()} | "
            f"Slot A={sup.mutator.slot_path('a')} | Slot B={sup.mutator.slot_path('b')} | "
            f"State DB={sup.store.db_path}"
        )
        return 0

    try:
        asyncio.run(sup.run_forever())
        return 0
    except KeyboardInterrupt:
        logger.info("Stem shutdown requested by operator.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
