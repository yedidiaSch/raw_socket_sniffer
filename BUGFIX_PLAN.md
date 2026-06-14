# Sniffer — Bug & Performance Remediation Plan

Status legend: ⬜ TODO · 🔧 IN PROGRESS · ✅ DONE

> **Update 2026-06-14:** All Phase 1 bugs fixed (B11 documented/deferred).
> Phase 2: P1, P2, P3 done. P4 (TPACKET_V3) and P5 (filter) deferred — see notes.

This document tracks all issues found in the deep review (2026-06-14) and the
plan to fix them. Bugs are fixed first, then performance improvements.

---

## Phase 1 — Bugs (correctness / safety)

### B1 — Unvalidated IHL in IPv4 parser  ⬜
- **File:** `layers/networkLayer.c:35`
- **Problem:** `*header_len = iph->ihl * 4;` uses the 4-bit IHL field without
  validating the legal range (5–15). A forged `ihl < 5` yields a header length
  smaller than the 20-byte minimum, so the transport pointer lands inside the
  IP header; `ihl*4 > size` overruns the buffer.
- **Fix:** Reject `ihl < 5`; clamp/validate `ihl*4 <= size` before returning.
  Return 0 (unknown) and set `*header_len = 0` on failure.

### B2 — No bounds check before transport dispatch  ⬜
- **File:** `core/managedMode.c:37`
- **Problem:** `transport_buffer = network_buffer + network_header_len` and
  `transport_remaining_size = network_remaining_size - network_header_len`
  computed without checking `network_header_len > 0` or that the result is
  non-negative. Bad L3 length (forged IHL, or IPv6 fixed 40 on a short buffer)
  produces an out-of-bounds pointer / negative size.
- **Fix:** Bail out if `network_header_len <= 0` or
  `transport_remaining_size < 0` before dispatching to L4.

### B3 — No SIGTERM handler → promisc mode never restored  ⬜
- **File:** `main.c:28`
- **Problem:** Only `SIGINT` is handled. `kill <pid>` (SIGTERM) kills the
  process instantly: promiscuous mode stays on, ring buffer not unmapped,
  logger thread not joined.
- **Fix:** Install the same handler for `SIGTERM`. Use `sigaction` for reliable
  semantics.

### B4 — `keep_running` should be `sig_atomic_t`  ⬜
- **File:** `main.c:11`
- **Problem:** Writing a plain `int` from a signal handler is only guaranteed
  safe for `volatile sig_atomic_t`.
- **Fix:** Change type to `volatile sig_atomic_t` (and the `extern` decl in
  `mmapSniffer.c:25`).

### B5 — EAPOL detection: fragile offset + false positives  ⬜
- **File:** `core/monitorMode.c:115-120`
- **Problem:** Byte scan starts at fixed `offset+24`, ignoring QoS (+2),
  HT Control (+4), and 4-address frames. The `AA AA 03 ... 88 8E` pattern can
  occur in encrypted payloads → encrypted frames misclassified as handshakes
  and written to the capture file.
- **Fix:** Compute the real 802.11 header length from frame-control flags
  (ToDS/FromDS for addr4, QoS subtype bit, Order/HT) and check the LLC/SNAP
  signature at the exact computed offset instead of scanning.

### B6 — `ftell` unchecked → corrupt PCAP  ⬜
- **File:** `core/monitorMode.c:242-245`
- **Problem:** `fseek`/`ftell` return values ignored; `ftell == -1` on error
  skips the global header, producing a headerless `.cap`.
- **Fix:** Check `fseek` and `ftell`; only write the header when `ftell`
  reliably reports 0.

### B7 — Socket leak on `inet_pton` failure  ⬜
- **File:** `common/udp_sender.c:29-33`
- **Problem:** `sockfd` opened on line 20 is not closed when `inet_pton` fails.
- **Fix:** `close(sockfd); sockfd = -1;` before returning -1.

### B8 — JSON injection via untrusted SSID  ⬜
- **File:** `common/udp_sender.c:97`
- **Problem:** SSID from a beacon is interpolated raw into JSON. A crafted SSID
  (`foo", "x": "`) injects arbitrary JSON into the dashboard stream.
- **Fix:** JSON-escape the SSID (and any other string from the wire) before
  embedding. Add a small `json_escape()` helper.

### B9 — WiFi 6E channels always report 0  ⬜
- **File:** `core/monitorMode.c:139`
- **Problem:** `if (freq < 2400 || freq > 6000) return 0;` excludes the 6 GHz
  band (5925–7125 MHz).
- **Fix:** Raise upper bound to ~7125 and add the 6 GHz channel formula
  `(freq - 5950) / 5`.

### B10 — Invalid CMake variable in `run` target  ⬜
- **File:** `CMakeLists.txt:89`
- **Problem:** `${CMAKE_PROJECT_DIR}` is not a real CMake variable → empty →
  wrong working directory.
- **Fix:** Use `${CMAKE_SOURCE_DIR}`.

### B11 — Extended radiotap present words ignored (low)  ⬜
- **File:** `core/monitorMode.c:195`
- **Problem:** Field presence checked only against the first `present` word;
  fields declared in extension words aren't handled. Channel/signal are
  normally in word 0, so impact is low — documenting for completeness.
- **Fix (optional):** Track per-namespace present bits if extension support is
  needed. Deferred unless required.

---

## Phase 2 — Performance

### P1 — Per-packet malloc/free in hot path  ⬜
- **File:** `common/logger.c:124,132,170`
- **Fix:** Pre-allocated node pool / fixed-size ring of `LogNode` instead of two
  heap allocations per packet.

### P2 — Double `vsnprintf` per text message  ⬜
- **File:** `common/logger.c:118-128`
- **Fix:** Single `vsnprintf` into a stack buffer; only `malloc` on overflow.

### P3 — Ring buffer too small (256 KB)  ⬜
- **File:** `core/mmapSniffer.c:83`
- **Fix:** Raise `tp_block_nr` to 512–1024 (2–4 MB).

### P4 — Using TPACKET_V2 instead of V3  ⏸ DEFERRED
- **File:** `core/mmapSniffer.c:64`
- **Decision:** Migrating to TPACKET_V3 block-based batching is the right
  long-term move, but it is a substantial rewrite of the capture loop (block
  descriptors, `tp_next_offset` walking, retire timeout) that can only be
  validated against live traffic with root — which can't be exercised in this
  environment. On a branch named `fix/runtime-stability`, shipping an
  unverified kernel-interface rewrite is the wrong trade. Left as a recommended
  follow-up to do with on-hardware testing.

### P5 — Every packet enqueued as UDP  ⏸ DEFERRED
- **File:** `core/packetParser.c:50`
- **Decision:** Adding a filter/rate-limit changes observable behaviour (the
  dashboard currently expects every packet). The original OOM risk is already
  removed by the bounded node pool (P1). Deferred as a product decision rather
  than imposed.

---

## Execution order
1. B1, B2, B4, B3 (memory safety + clean shutdown)
2. B7, B6, B9, B10 (small correctness)
3. B8 (JSON escaping)
4. B5 (EAPOL offset computation)
5. Build + verify
6. P2, P1, P3 (logger + ring)
7. P5, P4 (filter + TPACKET_V3) — evaluate/defer
