'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const subject = path.join(__dirname, '..', 'extension.js');

test('native launcher implementation exists', () => assert.equal(fs.existsSync(subject), true));

if (fs.existsSync(subject)) {
  const {launchCertifiedTask, verifyEnvelope, FROZEN_INITIAL_PROMPT, promptHash, validateManifest} = require(subject);
  const {privateKey, publicKey} = crypto.generateKeyPairSync('ed25519');
  const trust = {controller: publicKey.export({type: 'spki', format: 'pem'})};
  function fixture() {
    const manifest = {
      schema_version: 1, artifact_kind: 'native_launch', scope: 'synthetic',
      run_id: 'synthetic-1', task_id: 'synthetic:overflow', launch_id: 'launch-1', ordinal: 1,
      harness_sha256: 'a'.repeat(64), task_manifest_sha256: 'b'.repeat(64),
      workspace: '/workspace', container_id: 'c'.repeat(64), hostname: 'c'.repeat(12), uid: 1000,
      pid_namespace: 'pid:[100]', mount_namespace: 'mnt:[200]',
      remote_name: 'ssh-remote', vscode_version: '1.140.0',
      claude_extension_version: '2.1.289', claude_extension_sha256: 'd'.repeat(64),
      launcher_version: '0.1.0', prompt_sha256: promptHash(),
      native_launch_url: 'http://registered-tool-gateway/native-launch',
      file_hashes: {'CLAUDE.md': 'e'.repeat(64)},
    };
    const runtime = {
      platform: 'linux', remote_name: 'ssh-remote', workspace: '/workspace', uid: 1000,
      hostname: manifest.hostname, pid_namespace: 'pid:[100]', mount_namespace: 'mnt:[200]',
      pid: 321, ppid: 300, vscode_version: '1.140.0',
      claude_extension_version: '2.1.289', claude_extension_sha256: 'd'.repeat(64),
      claude_extension_kind: 2, launcher_version: '0.1.0', use_terminal: false,
      config_dir: '/home/agent/.claude', claude_extension_path: '/home/agent/.vscode-server/extensions/anthropic.claude-code-2.1.289',
      prior_session_state: false, environment_key_names: ['HOME', 'PATH'],
    };
    const calls = []; const state = new Map(); const receipts = []; const events = [];
    let claimed = false;
    const options = {
      manifest, runtime,
      vscode: {commands: {executeCommand: async (...args) => {calls.push(args);}}},
      state: {get: key => state.get(key), update: async (key, value) => state.set(key, value)},
      custody: {
        reserve: async receipt => {if (claimed) throw Error('already reserved'); assert.equal(calls.length, 0); claimed = true; receipts.push(receipt); return {status: 'reserved', launch_id: manifest.launch_id};},
        record: async event => events.push(event),
      },
      preflight: async () => {assert.equal(claimed,true);assert.equal(calls.length,0);},
      writeReceipt: async receipt => {assert.equal(calls.length, 0); assert.equal(claimed, true);},
      now: () => '2026-10-05T00:00:00.000Z',
    };
    return {options, calls, state, receipts, events};
  }
  test('verifies actual Xeus wire envelope and rejects altered payload', () => {
    const {options} = fixture();
    const payload = Buffer.from(JSON.stringify(options.manifest));
    const envelope = {algorithm: 'Ed25519', key_id: 'controller', payload: payload.toString('base64'), signature: crypto.sign(null, payload, privateKey).toString('base64')};
    assert.deepEqual(verifyEnvelope(envelope, trust), options.manifest);
    assert.throws(() => verifyEnvelope({...envelope, payload: Buffer.from('{}').toString('base64')}, trust), /signature/);
    assert.throws(() => verifyEnvelope(envelope, {}), /signature/);
    assert.throws(() => verifyEnvelope({...envelope, payload: envelope.payload + '\n'}, trust), /signature/);
  });
  test('durably reserves before exactly one native panel command; reload never relaunches', async () => {
    const f = fixture();
    const result = await launchCertifiedTask(f.options);
    assert.equal(result.status, 'command_returned');
    assert.deepEqual(f.calls, [['claude-vscode.editor.open', undefined, FROZEN_INITIAL_PROMPT, undefined, undefined, true, {programmatic: 'pin-to-panel'}]]);
    assert.equal(f.receipts[0].session_id, null);
    assert.equal(f.receipts[0].observed.pid, 321);
    assert.equal(f.events[0].event, 'command_returned');
    await assert.rejects(launchCertifiedTask(f.options), /already launched/);
    f.state.clear();
    await assert.rejects(launchCertifiedTask(f.options), /already reserved/);
    assert.equal(f.calls.length, 1);
  });
  for (const [key, value] of Object.entries({platform:'win32', remote_name:undefined, uid:0, hostname:'host', pid_namespace:'pid:[999]', mount_namespace:'mnt:[999]', vscode_version:'1.141.0', claude_extension_version:'2.1.290', claude_extension_sha256:'f'.repeat(64), claude_extension_kind:1, workspace:'/home/agent', use_terminal:true, prior_session_state:true, config_dir:'/root/.claude'})) {
    test(`rejects unsafe runtime ${key} before reservation`, async () => {
      const f = fixture(); f.options.runtime[key] = value;
      await assert.rejects(launchCertifiedTask(f.options), /runtime|session/);
      assert.equal(f.receipts.length, 0); assert.equal(f.calls.length, 0);
    });
  }
  test('receipt write failure consumes reservation without launching or retry', async () => {
    const f = fixture(); f.options.writeReceipt = async () => {throw Error('disk full');};
    await assert.rejects(launchCertifiedTask(f.options), /disk full/);
    assert.equal(f.calls.length, 0);
    await assert.rejects(launchCertifiedTask(f.options), /already reserved/);
  });
  test('parent preflight failure consumes reservation before any model command', async () => {
    const f=fixture();f.options.preflight=async()=>{throw Error('probe failed');};
    await assert.rejects(launchCertifiedTask(f.options),/preflight failed/);
    assert.equal(f.calls.length,0);
    assert.equal(f.events[0].event,'preflight_failed');
    await assert.rejects(launchCertifiedTask(f.options),/already launched/);
  });
  test('command failure is recorded once without logging its secret-bearing error', async () => {
    const f = fixture(); f.options.vscode.commands.executeCommand = async () => {f.calls.push('attempt'); throw Error('secret-token');};
    await assert.rejects(launchCertifiedTask(f.options), /native command failed/);
    assert.equal(f.calls.length, 1); assert.equal(f.events[0].event, 'command_failed');
    assert.equal(JSON.stringify(f.events).includes('secret-token'), false);
    await assert.rejects(launchCertifiedTask(f.options), /already launched/);
  });
  test('concurrent windows receive only one reservation', async () => {
    const f = fixture();
    const results = await Promise.allSettled([launchCertifiedTask(f.options), launchCertifiedTask(f.options)]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(f.calls.length, 1);
  });
  for (const patch of [{prompt_sha256:'0'.repeat(64)}, {ordinal:0}, {native_launch_url:'https://public.example/native-launch'}, {workspace:'/tmp/escape'}, {file_hashes:{'../secret':'a'.repeat(64)}}, {extra:'unrecognised'}]) {
    test(`rejects malformed manifest ${JSON.stringify(patch)}`, () => assert.throws(() => validateManifest({...fixture().options.manifest, ...patch}), /manifest/));
  }
  test('process environment must match frozen public sentinel settings without personal auth',()=>{
    const {validateProcessConfig}=require(subject);
    assert.equal(typeof validateProcessConfig,'function');
    const frozen=require('../machine-settings.json')['claudeCode.environmentVariables'];
    const config=values=>({get:(key,fallback)=>key==='environmentVariables'?values:fallback});
    assert.doesNotThrow(()=>validateProcessConfig(config(frozen)));
    assert.throws(()=>validateProcessConfig(config([...frozen,{name:'CLAUDE_CODE_OAUTH_TOKEN',value:'personal-secret'}])),/unfrozen/);
    assert.throws(()=>validateProcessConfig(config([])),/unfrozen/);
  });
}
