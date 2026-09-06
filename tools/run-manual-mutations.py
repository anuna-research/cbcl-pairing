#!/usr/bin/env python3
"""Bounded local guard-removal evidence, SPEC-078 TEST-001/002/003/006/007.
Restores each source in finally. Never changes dependencies, specifications or wire.
Each killed mutant must execute a Rust test and fail behaviorally (not compilation).
Run alone in this worktree: python3 tools/run-manual-mutations.py [name ...]
"""
import json
import os
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence/manual-pairing/mutations'
ENV = dict(os.environ, CARGO_TARGET_DIR='/Volumes/anuna-03/codex-spec078-pairing-target',
           CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0')
MANUAL = 'src/credential_v2/manual.rs'
BOOT = 'src/credential_v2/bootstrap.rs'
ALLOC = 'src/credential_v2/allocator.rs'
codec = ['--test', 'credential_v2_manual']
session = ['--test', 'credential_v2_manual_session']
inner = ['--lib', 'credential_v2::bootstrap::tests']
mutations = []
def add(name, file, old, new, tests):
    mutations.append((name, file, [(old, new)], tests))
add('word-domain', MANUAL, 'b"selfsame-pairing-manual-words/v1\\0"', 'b""', codec)
add('c-mapping-domain', MANUAL, 'b"SSPAIR-M1\\0\\0\\0"', 'b"SSPAIR-M2\\0\\0\\0"', codec)
add('word-byte-order', MANUAL, 'u32::from_be_bytes(random)', 'u32::from_le_bytes(random)', codec)
add('uniform-mask', MANUAL, 'u32::from_be_bytes(random) & 0x3fff_ffff', 'u32::from_be_bytes(random)', codec)
add('packing-shift', MANUAL, 'u64::from(*n) << 3', 'u64::from(*n) << 2', codec)
add('first-index-shift', MANUAL, '[22, 11, 0]', '[21, 11, 0]', codec)
add('second-index-shift', MANUAL, '[22, 11, 0]', '[22, 10, 0]', codec)
add('checksum-comparison', MANUAL, 'if !bool::from(checksum(*n).ct_eq(&((*bits & 7) as u8)))', 'if false && !bool::from(checksum(*n).ct_eq(&((*bits & 7) as u8)))', codec)
add('bootstrap-domain', MANUAL, 'b"selfsame-pairing-manual/v1"', 'b"selfsame-pairing-manual/v2"', codec)
add('phrase-bound', MANUAL, 'if input.len() > MAX_PHRASE', 'if false && input.len() > MAX_PHRASE', codec)
add('bootstrap-bound', MANUAL, 'if input.len() > MAX_TEXT', 'if false && input.len() > MAX_TEXT', codec)
add('separator-language', MANUAL, ".split([' ', '\\t', '\\r', '\\n'])", '.split_ascii_whitespace()', codec)
mutations.append(('complete-bootstrap', MANUAL, [
    ('if !parser.0.is_empty()', 'if false && !parser.0.is_empty()'),
    ('if bootstrap.encode()?.as_bytes() != input.as_bytes()', 'if false && bootstrap.encode()?.as_bytes() != input.as_bytes()')], codec))
add('claim-commitment', MANUAL, 'if !bool::from(\n            claim_commitment', 'if false && !bool::from(\n            claim_commitment', codec)
add('allocator-key', MANUAL, 'if carrier.expected_allocator_key().is_none()', 'if false && carrier.expected_allocator_key().is_none()', codec)
add('exclusive-expiry', MANUAL, 'if now >= carrier.relay_expires_at()', 'if now > carrier.relay_expires_at()', codec)
add('authenticated-mode-encoding', BOOT, 'CredentialV2AllocatorMode::Manual => 1,', 'CredentialV2AllocatorMode::Manual => 0,', inner)
add('expected-mode', BOOT, 'if mode != expected_mode', 'if false && mode != expected_mode', inner)
add('old-restore-full', BOOT, 'if tag == OLD_INNER_DOMAIN {\n            CredentialV2AllocatorMode::Full', 'if tag == OLD_INNER_DOMAIN {\n            CredentialV2AllocatorMode::Manual', inner)
add('full-export', BOOT, 'if self.mode != CredentialV2AllocatorMode::Full', 'if false && self.mode != CredentialV2AllocatorMode::Full', session)
add('legacy-export', BOOT, '(self.mode == CredentialV2AllocatorMode::Full)', '(true)', session)
add('manual-export', BOOT, 'if self.mode != CredentialV2AllocatorMode::Manual', 'if false && self.mode != CredentialV2AllocatorMode::Manual', session)
add('pre-peer-zero-scalar', ALLOC, '.then(|| Zeroizing::new(*fresh_cpace_scalar))', '.then(|| Zeroizing::new([0; 32]))', session + ['pre_peer_restore'])
add('retained-share-check', BOOT, 'if bootstrap.cached_outbound.as_ref() != Some(&CredentialV2Frame::cpace(&message)?)', 'if false && bootstrap.cached_outbound.as_ref() != Some(&CredentialV2Frame::cpace(&message)?)', inner)
add('retained-finished-check', BOOT, 'if self.cached_outbound.as_ref() != Some(&pending.local_finished_frame())', 'if false && self.cached_outbound.as_ref() != Some(&pending.local_finished_frame())', inner)
add('one-distinct-peer', ALLOC, 'if bootstrap.peer_cpace() != Some(&frame)', 'if false && bootstrap.peer_cpace() != Some(&frame)', session)
add('persistence-before-output', ALLOC, 'self.after_persist = after;\n        Ok(vec![CredentialV2AllocatorEffect::Checkpoint {', 'self.after_persist = after;\n        if !self.after_persist.is_empty() { return Ok(std::mem::take(&mut self.after_persist)); }\n        Ok(vec![CredentialV2AllocatorEffect::Checkpoint {', session)
add('blocked-reentrant-output', ALLOC, 'if self.persistence_gate.is_some() {\n            return Err(CredentialV2Error::Phase);\n        }\n        let result = decode_server_message', 'if false && self.persistence_gate.is_some() {\n            return Err(CredentialV2Error::Phase);\n        }\n        let result = decode_server_message', session)
add('terminal-export', ALLOC, 'fn terminate(&mut self) {\n        self.state = AllocatorState::Terminal;', 'fn terminate(&mut self) {', session)
add('terminal-scalar-erasure', ALLOC, 'self.cpace_scalar = None;\n        self.wrapping_key.zeroize();', 'self.wrapping_key.zeroize();', ['--lib', 'terminal_input_erases'])
add('terminal-presence-erasure', ALLOC, 'self.presence = None;\n        self.cpace_scalar = None;', 'self.cpace_scalar = None;', ['--lib', 'terminal_input_erases'])
add('terminal-key-erasure', ALLOC, 'self.wrapping_key.zeroize();', '', ['--lib', 'terminal_input_erases'])
add('contact-provenance', 'src/credential_v2/display.rs', 'tofu_state: authority.tofu_state,', 'tofu_state: CredentialV2TofuState::TrustedPair,', ['--test', 'credential_v2_display', 'ceremony_contact'])


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    selected = [m for m in mutations if len(sys.argv) == 1 or m[0] in sys.argv[1:]]
    if not selected:
        raise SystemExit('no matching mutant')
    results_path = OUT/'results.json'
    results = json.loads(results_path.read_text()) if results_path.exists() else []
    for name, file, changes, tests in selected:
        path = ROOT / file
        original = path.read_text()
        mutated = original
        for old, new in changes:
            pattern = r'\s+'.join(re.escape(part) for part in old.split())
            matches = list(re.finditer(pattern, mutated))
            if len(matches) != 1:
                raise RuntimeError(f'{name}: expected one source anchor, got {len(matches)}')
            match = matches[0]
            mutated = mutated[:match.start()] + new + mutated[match.end():]
        command = ['cargo', 'test', '--offline'] + tests
        try:
            path.write_text(mutated)
            run = subprocess.run(command, cwd=ROOT, env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (OUT / (name+'.log')).write_text(run.stdout)
            behavioral = run.returncode != 0 and 'test result: FAILED' in run.stdout and 'error[E' not in run.stdout
            result = dict(name=name, source=file, changes=changes, command=command, exit_code=run.returncode,
                          behavioral_red=behavioral, log=name+'.log')
            results = [r for r in results if r["name"] != name] + [result]
            (OUT/'results.json').write_text(json.dumps(results, indent=2)+'\n')
            print(name, 'BEHAVIORAL_RED' if behavioral else 'NOT_KILLED', flush=True)
            if not behavioral:
                raise RuntimeError(f'{name}: no behavioral red; see log')
        finally:
            path.write_text(original)

if __name__ == '__main__':
    main()
