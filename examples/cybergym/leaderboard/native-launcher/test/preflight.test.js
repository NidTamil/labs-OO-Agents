'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const {runNativePreflight}=require(path.join(__dirname,'../native-preflight.js'));

test('native preflight executes exact controller probes with no captured output',async()=>{
  const manifest={run_id:'r1',task_id:'synthetic:1',launch_id:'l1',native_launch_url:'http://registered-tool-gateway/native-launch'};
  const calls=[]; const executed=[];
  const post=async(url,body)=>{
    calls.push([url,body]);
    if(url.endsWith('/begin')) return {nonce:'a'.repeat(32),probes:[
      {name:'uid',command:['/usr/bin/python3','-c','raise SystemExit(0)']},
      {name:'tool:clangd',command:['/usr/bin/python3','-c','raise SystemExit(0)']},
    ]};
    return {passed:true,report_sha256:'b'.repeat(64)};
  };
  const spawn=(file,args,options)=>{executed.push([file,args,options]);return {status:0,stdout:undefined,stderr:undefined};};
  const result=await runNativePreflight(manifest,'child','agent-1',post,spawn);
  assert.equal(result.report_sha256,'b'.repeat(64));
  assert.deepEqual(calls.map(item=>item[0]),[
    manifest.native_launch_url+'/preflight/begin',manifest.native_launch_url+'/preflight/submit'
  ]);
  assert.deepEqual(calls[1][1].results,[{name:'uid',exit_code:0},{name:'tool:clangd',exit_code:0}]);
  assert.equal(executed.length,2);
  assert.equal(executed[0][2].stdio,'ignore');
  assert.equal(executed[0][2].cwd,'/workspace');
  assert.equal(calls[1][1].agent_id,'agent-1');
});

test('native preflight never admits an incomplete or failed controller receipt',async()=>{
  const manifest={run_id:'r1',task_id:'synthetic:1',launch_id:'l1',native_launch_url:'http://registered-tool-gateway/native-launch'};
  const post=async(url)=>url.endsWith('/begin')
    ? {nonce:'a'.repeat(32),probes:[{name:'uid',command:['/usr/bin/python3','-c','pass']}]}
    : {passed:false};
  await assert.rejects(runNativePreflight(manifest,'parent',null,post,()=>({status:1})),/preflight/);
});
