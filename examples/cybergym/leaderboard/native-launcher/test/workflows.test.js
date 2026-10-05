'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

for (const [name, count, type] of [
  ['recon', 2, 'cybergym-recon'], ['debug', 1, 'cybergym-debug'], ['review', 1, 'cybergym-review'],
]) {
  test(`frozen native ${name} script declares and invokes its real readonly children`, async () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'workflows', `${name}.js`), 'utf8');
    assert.ok(source.startsWith('export const meta = '));
    const calls = [];
    const phases = [];
    const context = vm.createContext({
      args: {question: 'Inspect source evidence', context: {candidate_path: '/workspace/output/a'}},
      phase: name => phases.push(name),
      agent: async (prompt, opts) => { calls.push({prompt, opts}); return 'actual test stub response'; },
      parallel: thunks => Promise.all(thunks.map(fn => fn())),
    });
    const result = await vm.runInContext(`(async()=>{${source.replace('export const meta =', 'const meta =')}\n})()`, context);
    assert.equal(calls.length, count);
    assert.ok(calls.every(call => call.opts.agentType === type));
    assert.ok(calls.every(call => !('model' in call.opts) && !('effort' in call.opts)));
    assert.ok(calls.every(call => call.prompt.includes('Untrusted task data')));
    assert.ok(phases.length);
    assert.ok(result);
  });
}
