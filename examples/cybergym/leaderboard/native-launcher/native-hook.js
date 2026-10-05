'use strict';
const fs=require('node:fs'); const crypto=require('node:crypto'); const path=require('node:path');
const {canonical,verifyEnvelope,postJson}=require('./extension');
const EVENTS=new Set(['SessionStart','SessionEnd','SubagentStart','SubagentStop','PreToolUse','PostToolUse','PostToolUseFailure','Stop','StopFailure']);
function text(value,optional=false) {if(value==null&&optional)return null;if(typeof value!=='string'||!/^[A-Za-z0-9][A-Za-z0-9:_.\[\]/-]{0,255}$/.test(value))throw Error('invalid hook identifier');return value;}
function transcript(value,optional=false) {if(value==null&&optional)return null;if(typeof value!=='string'||value.length>1024||!value.startsWith('/home/agent/.claude/projects/')||!value.endsWith('.jsonl')||path.posix.normalize(value)!==value||value.split('/').includes('..')||!/^[A-Za-z0-9/_.-]+$/.test(value))throw Error('invalid hook transcript path');return value;}
function projectHookInput(raw) {
  if(!raw||!EVENTS.has(raw.hook_event_name)||typeof raw.cwd!=='string'||!(raw.cwd==='/workspace'||raw.cwd.startsWith('/workspace/'))||path.posix.normalize(raw.cwd)!==raw.cwd||raw.cwd.split('/').includes('..'))throw Error('invalid hook identity');
  const result={hook_event_name:raw.hook_event_name,session_id:text(raw.session_id),agent_id:text(raw.agent_id,true),agent_type:text(raw.agent_type,true),tool_name:text(raw.tool_name,true),tool_use_id:text(raw.tool_use_id,true),model:text(raw.model,true),source:text(raw.source,true),effort:text(raw.effort?.level,true),transcript_path:transcript(raw.transcript_path),agent_transcript_path:transcript(raw.agent_transcript_path,true),cwd:raw.cwd,raw_input_sha256:crypto.createHash('sha256').update(canonical(raw)).digest('hex')};
  if(result.hook_event_name.startsWith('Subagent')&&(!result.agent_id||!result.agent_type))throw Error('missing child identity');
  if(['PreToolUse','PostToolUse','PostToolUseFailure'].includes(result.hook_event_name)&&(!result.tool_name||!result.tool_use_id))throw Error('missing tool identity');
  return result;
}
async function main() {
  let raw;
  try {
    const chunks=[];let size=0;
    for await(const chunk of process.stdin) {size+=chunk.length;if(size>8*1024*1024)throw Error('hook input too large');chunks.push(chunk);}
    raw=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const manifest=verifyEnvelope(JSON.parse(fs.readFileSync('/workspace/.sunchaser/launch.json','utf8')),JSON.parse(fs.readFileSync('/etc/sunchaser/native-launch-trust.json','utf8')));
    process.stdout.write(JSON.stringify(await processNativeHook(raw,manifest))+'\n');
  } catch {
    // No raw tool data or provider errors enter stdout/stderr.
    if(raw?.hook_event_name==='PreToolUse') {
      process.stdout.write(JSON.stringify({hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'deny',permissionDecisionReason:'Native telemetry is unavailable.'}})+'\n');
    } else {process.stderr.write('Native telemetry is unavailable.\n');process.exitCode=2;}
  }
}
async function processNativeHook(raw,manifest,post=postJson) {
  const identity={schema_version:1,run_id:manifest.run_id,task_id:manifest.task_id,launch_id:manifest.launch_id};
  const projection=projectHookInput(raw);
  let decision;
  if(raw.hook_event_name==='PreToolUse') {
    const result=await post('http://registered-tool-gateway/native-tools/authorize',{...identity,hook_input:raw});
    if(!['allow','deny'].includes(result.permissionDecision))throw Error('tool authorization unavailable');
    decision=result.permissionDecision;
  }
  if(['PostToolUse','PostToolUseFailure'].includes(raw.hook_event_name)) {
    const result=await post('http://registered-tool-gateway/native-tools/result',{...identity,hook_input:raw});
    if(result.recorded!==true)throw Error('tool result custody unavailable');
  }
  const result=await post(manifest.native_launch_url+'/hooks',{...identity,event_id:crypto.randomUUID(),hook:projection});
  if(!['recorded','duplicate'].includes(result.status))throw Error('hook evidence rejected');
  return decision?{hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:decision,permissionDecisionReason:decision==='allow'?'Controller tool policy allowed this invocation.':'Controller tool policy denied this invocation.'}}:{};
}
if(require.main===module)main();
module.exports={projectHookInput,processNativeHook};
