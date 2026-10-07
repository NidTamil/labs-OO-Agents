'use strict';
const {spawnSync}=require('node:child_process');

const ID=/^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$/;
const PROBE=/^[A-Za-z0-9][A-Za-z0-9:_./*\-]{0,255}$/;
const AGENT=/^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/;
const SHA=/^[a-f0-9]{64}$/;

async function runNativePreflight(manifest,context,agentId,post,spawn=spawnSync) {
  if(!manifest||!['run_id','task_id','launch_id','native_launch_url'].every(k=>typeof manifest[k]==='string')||
      !['run_id','task_id','launch_id'].every(k=>ID.test(manifest[k]))||
      !/^http:\/\/registered-tool-gateway(?::80)?\/native-launch$/.test(manifest.native_launch_url)||
      !['parent','child'].includes(context)||
      (context==='parent'?agentId!==null:typeof agentId!=='string'||!AGENT.test(agentId))||
      typeof post!=='function'||typeof spawn!=='function') throw Error('native preflight identity invalid');
  const identity={schema_version:1,run_id:manifest.run_id,task_id:manifest.task_id,launch_id:manifest.launch_id,context,agent_id:agentId};
  const base=manifest.native_launch_url+'/preflight';
  const issued=await post(base+'/begin',identity);
  if(!issued||typeof issued.nonce!=='string'||!(/^[a-f0-9]{32}$/.test(issued.nonce))||
      !Array.isArray(issued.probes)||issued.probes.length===0||issued.probes.length>256) throw Error('native preflight issuance invalid');
  const seen=new Set(); const results=[];
  for(const probe of issued.probes) {
    if(!probe||typeof probe.name!=='string'||!PROBE.test(probe.name)||seen.has(probe.name)||
        !Array.isArray(probe.command)||probe.command.length<3||probe.command.length>8||
        probe.command[0]!=='python3'||probe.command[1]!=='-c'||
        probe.command.some(part=>typeof part!=='string'||part.length>16384||part.includes('\0'))) {
      throw Error('native preflight probe invalid');
    }
    seen.add(probe.name);
    let exitCode=1;
    try {
      const executed=spawn(probe.command[0],probe.command.slice(1),{
        cwd:'/workspace',env:process.env,stdio:'ignore',shell:false,timeout:15000,
      });
      if(Number.isInteger(executed.status)&&executed.status>=0&&executed.status<=255) exitCode=executed.status;
    } catch { /* No command output or exception text crosses the boundary. */ }
    results.push({name:probe.name,exit_code:exitCode});
  }
  const receipt=await post(base+'/submit',{...identity,nonce:issued.nonce,results});
  if(!receipt||receipt.passed!==true||typeof receipt.report_sha256!=='string'||!SHA.test(receipt.report_sha256)) throw Error('native preflight not admitted');
  return {report_sha256:receipt.report_sha256};
}

module.exports={runNativePreflight};
