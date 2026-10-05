import { test, expect } from 'bun:test';
import { checkedGrant, checkedWriterGrant, NativeSession, normalizeResult } from './runtime.ts';
import { withAIInvocationGuard, hasAIInvocationGuard, invokeAI } from '/root/.bun/install/global/node_modules/gbrain/src/core/ai/invocation-guard.ts';

const source = 'xeus-cybergym-workspace';
const auth = { clientId: 'synthetic-reader', principal: {kind:'oauth_client'}, sourceId: source,
  allowedSources: [source], scopes: ['read'], sourceActive: true, allowedOperations: ['recall','search','get_page'] };

test('authenticated wider source grant cannot become exact by request arguments', () => {
  expect(() => checkedGrant({...auth, allowedSources:[source,'default']})).toThrow();
  expect(() => checkedGrant({...auth, scopes:['read','write']})).toThrow();
  expect(checkedGrant(auth).sourceId).toBe(source);
});

test('real installed AsyncLocalStorage guard encloses native dispatch and settlement', async () => {
  const observed:any[] = [];
  const native = {
    verify: async () => auth, withAIInvocationGuard, hasAIInvocationGuard,
    tools: [{name:'recall', inputSchema:{type:'object'}}], version:'test', metadata:{},
    dispatch: async (_name:any, _args:any, options:any) => {
      expect(options.sourceId).toBe(source);
      expect(options.auth.allowedSources).toEqual([source]);
      return invokeAI({model:'test:model',kind:'embedding',operation:'embed'}, async () => {
        observed.push('provider'); return {ok:true};
      }, () => ({inputTokens:3,outputTokens:0}));
    },
  };
  const session = new NativeSession(native as any, async (frame:any) => {
    observed.push(frame.type); return true;
  });
  const result = await session.handle({id:'1',method:'tools/call',params:{name:'recall',arguments:{query:'generic'}}});
  expect(result.result).toEqual({ok:true});
  expect(observed).toEqual(['guard_admit','provider','guard_settle']);
});

test('missing budget permission prevents provider call and default source/write are rejected', async () => {
  let calls = 0;
  const native = { verify:async()=>auth, withAIInvocationGuard, hasAIInvocationGuard,
    tools:[], version:'test', metadata:{}, dispatch: async()=> {
      return invokeAI({model:'test:model',kind:'embedding',operation:'embed'}, async()=>{calls++;return {};},()=>null);
    } };
  const session = new NativeSession(native as any, async()=>false);
  for (const [name,args] of [['capture',{}],['search',{source_id:'default'}],['recall',{query:'generic'}]] as any) {
    expect((await session.handle({id:'1',method:'tools/call',params:{name,arguments:args}})).error).toBeDefined();
  }
  expect(calls).toBe(0);
});

test('native search retrieval summary becomes metadata without loosening ambiguous results', () => {
  const result = {content:[{type:'text',text:'[]'},{type:'text',text:'0 results. retrieved 0 before trimming.'}],
    _meta:{retrieval:{returned_count:0}}};
  expect(normalizeResult('search',result).content).toEqual([{type:'text',text:'[]'}]);
  expect(normalizeResult('search',result)._meta.xeus_native_summary).toBe(result.content[1].text);
  expect(() => normalizeResult('search',{...result,content:[...result.content,{type:'text',text:'secret'}]})).toThrow();
});

test('controller auxiliary certification is guarded and cannot accept solver supplied prompts', async () => {
  const native = {verify:async()=>auth,withAIInvocationGuard,hasAIInvocationGuard,
    probe:async()=>({guarded:hasAIInvocationGuard()})};
  const session=new NativeSession(native as any,async()=>true);
  expect((await session.handle({id:'c',method:'xeus/certify-native-models',params:{}})).result).toEqual({guarded:true});
  expect((await session.handle({id:'c',method:'xeus/certify-native-models',params:{prompt:'untrusted'}})).error).toBeDefined();
});

test('separate writer grant restricts captures to episodic namespace and read session cannot write', async () => {
  const writerAuth={...auth,scopes:['read','write'],allowedOperations:['capture'],boundSlugPrefixes:['cybergym/episodic/']};
  expect(checkedWriterGrant(writerAuth).sourceId).toBe(source);
  expect(()=>checkedWriterGrant({...writerAuth,boundSlugPrefixes:null})).toThrow();
  const calls:any[]=[];
  const native={mode:'writer',verify:async()=>writerAuth,withAIInvocationGuard,hasAIInvocationGuard,
    dispatch:async(name:any,args:any,opts:any)=>{calls.push([name,args,opts.sourceId]);return {captured:true};}};
  const session=new NativeSession(native as any,async()=>true);
  const message={id:'w',method:'xeus/oracle-capture',params:{arguments:{slug:'cybergym/episodic/synthetic',content:'generic outcome',type:'note'}}};
  expect((await session.handle(message)).result).toEqual({captured:true});
  expect(calls[0][2]).toBe(source);
  expect((await session.handle({...message,params:{arguments:{...message.params.arguments,slug:'cybergym/principle/bad'}}})).error).toBeDefined();
  expect((await session.handle({...message,method:'tools/call'})).error).toBeDefined();
  const reader=new NativeSession({...native,mode:'read',verify:async()=>auth} as any,async()=>true);
  expect((await reader.handle(message)).error).toBeDefined();
});
