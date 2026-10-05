'use strict';
const test=require('node:test'); const assert=require('node:assert/strict'); const fs=require('node:fs'); const path=require('node:path');
const file=path.join(__dirname,'../native-hook.js');
test('native hook sender exists',()=>assert.equal(fs.existsSync(file),true));
if(fs.existsSync(file)) {
  const {projectHookInput,processNativeHook}=require(file);
  test('projects actual 2.1.289 native hook fields without secret-bearing content',()=>{
    const hook=projectHookInput({session_id:'session-1',hook_event_name:'PreToolUse',cwd:'/workspace/src',transcript_path:'/home/agent/.claude/projects/-workspace/session-1.jsonl',agent_id:'a1234',tool_name:'Bash',tool_use_id:'toolu_1',tool_input:{command:'echo secret-token'},effort:{level:'max'}});
    assert.equal(hook.agent_id,'a1234');assert.equal(hook.effort,'max');assert.equal(hook.raw_input_sha256.length,64);
    assert.equal(JSON.stringify(hook).includes('secret-token'),false);
  });
  test('rejects nonexistent synthetic hook kinds and path escape',()=>{
    const base={session_id:'session-1',hook_event_name:'SessionStart',cwd:'/workspace',transcript_path:'/home/agent/.claude/projects/-workspace/session-1.jsonl'};
    assert.throws(()=>projectHookInput({...base,hook_event_name:'AgentSpawned'}));
    assert.throws(()=>projectHookInput({...base,transcript_path:'/home/agent/.claude/projects/../../secret.jsonl'}));
  });
  test('PreToolUse sends exact input to controller and only emits safe native decision',async()=>{
    const raw={session_id:'session-1',hook_event_name:'PreToolUse',cwd:'/workspace',transcript_path:'/home/agent/.claude/projects/-workspace/session-1.jsonl',tool_name:'Bash',tool_use_id:'toolu_1',tool_input:{command:'true'}};
    const manifest={run_id:'r1',task_id:'synthetic:1',launch_id:'l1',native_launch_url:'http://registered-tool-gateway/native-launch'};
    const calls=[];
    const result=await processNativeHook(raw,manifest,async(url,body)=>{calls.push([url,body]);return url.endsWith('/authorize')?{permissionDecision:'deny',secret:'must-not-echo'}:{status:'recorded'};});
    assert.equal(calls[0][0],'http://registered-tool-gateway/native-tools/authorize');
    assert.deepEqual(calls[0][1].hook_input,raw);
    assert.equal(calls[1][0],manifest.native_launch_url+'/hooks');
    assert.equal(result.hookSpecificOutput.permissionDecision,'deny');
    assert.equal(JSON.stringify(result).includes('must-not-echo'),false);
  });
  test('PostToolUse requires controller result custody before observation succeeds',async()=>{
    const raw={session_id:'session-1',hook_event_name:'PostToolUse',cwd:'/workspace',transcript_path:'/home/agent/.claude/projects/-workspace/session-1.jsonl',tool_name:'Read',tool_use_id:'toolu_1',tool_input:{file_path:'/workspace/CLAUDE.md'},tool_response:'result'};
    const manifest={run_id:'r1',task_id:'synthetic:1',launch_id:'l1',native_launch_url:'http://registered-tool-gateway/native-launch'};
    const calls=[];
    await processNativeHook(raw,manifest,async(url,body)=>{calls.push([url,body]);return url.endsWith('/result')?{recorded:true}:{status:'recorded'};});
    assert.equal(calls[0][0],'http://registered-tool-gateway/native-tools/result');
    assert.deepEqual(calls[0][1].hook_input,raw);
    await assert.rejects(processNativeHook(raw,manifest,async()=>({recorded:false})),/result custody/);
  });
}
