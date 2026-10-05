/** Controller-only native GBrain sidecar. No listener and no solver credentials. */
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync, lstatSync, readdirSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';

export const SOURCE = 'xeus-cybergym-workspace';
export const PROFILE = '/srv/sunchaser/gbrain-profiles/xeus-cybergym';
export const PACKAGE = '/root/.bun/install/global/node_modules/gbrain';
export const READS = ['recall', 'search', 'get_page'];
const sha = (input: string | Buffer) => createHash('sha256').update(input).digest('hex');

export function normalizeResult(name:string,result:any) {
  if (name !== 'search' || result?.content?.length === 1) return result;
  if (result?.content?.length !== 2 || result.content.some((part:any)=>part.type !== 'text')
      || !result._meta?.retrieval || !/^\d+ results\. retrieved \d+ before trimming\./.test(result.content[1].text)
      || !Array.isArray(JSON.parse(result.content[0].text))) throw new Error('ambiguous_native_result');
  return {...result,content:[result.content[0]],
    _meta:{...result._meta,xeus_native_summary:result.content[1].text}};
}

export function checkedGrant(auth: any) {
  if (auth?.principal?.kind !== 'oauth_client' || !auth.clientId || auth.sourceId !== SOURCE
      || auth.sourceActive !== true || JSON.stringify(auth.allowedSources) !== JSON.stringify([SOURCE])
      || JSON.stringify(auth.scopes) !== JSON.stringify(['read'])
      || !Array.isArray(auth.allowedOperations)
      || READS.some(name => !auth.allowedOperations.includes(name))
      || auth.allowedOperations.some((name:string) => !READS.includes(name))) {
    throw new Error('exact_read_grant_required');
  }
  return auth;
}

export function checkedWriterGrant(auth:any) {
  if (auth?.principal?.kind !== 'oauth_client' || !auth.clientId || auth.sourceId !== SOURCE
      || auth.sourceActive !== true || JSON.stringify(auth.allowedSources) !== JSON.stringify([SOURCE])
      || JSON.stringify(auth.scopes) !== JSON.stringify(['read','write'])
      || JSON.stringify(auth.allowedOperations) !== JSON.stringify(['capture'])
      || JSON.stringify(auth.boundSlugPrefixes) !== JSON.stringify(['cybergym/episodic/'])) {
    throw new Error('exact_capture_grant_required');
  }
  return auth;
}

export class NativeSession {
  constructor(private native: any, private permit: (frame:any)=>Promise<boolean>) {}

  async handle(message:any) {
    const id = message.id;
    try {
      const writer=this.native.mode==='writer';
      const auth = (writer?checkedWriterGrant:checkedGrant)(await this.native.verify());
      return await this.native.withAIInvocationGuard(async (invocation:any) => {
        const permitId = randomUUID();
        if (!await this.permit({type:'guard_admit',id:permitId,request_id:id,invocation})) {
          throw new Error('controller_admission_denied');
        }
        return {settle:async (usage:any) => {
          if (!await this.permit({type:'guard_settle',id:permitId,request_id:id,usage})) {
            throw new Error('controller_settlement_denied');
          }
        }};
      }, async () => {
        if (!this.native.hasAIInvocationGuard()) throw new Error('guard_unbound');
        let result:any;
        switch (message.method) {
          case 'xeus/evidence':
            result = {...this.native.metadata, source_ids:auth.allowedSources,
              server_context_source_id:auth.sourceId, scopes:auth.scopes, client_id:auth.clientId,
              grant_revision:auth.grantRevision, expires_at:auth.expiresAt,
              session_mode:writer?'writer':'read', allowed_operations:auth.allowedOperations,
              native_guard_bound:this.native.hasAIInvocationGuard(), transport:'native-guarded-stdio'};
            break;
          case 'initialize':
            result = {protocolVersion:'2025-06-18', capabilities:{tools:{}},
              serverInfo:{name:'gbrain',version:this.native.version}};
            break;
          case 'notifications/initialized': return null;
          case 'tools/list': result = {tools:this.native.tools}; break;
          case 'xeus/certify-native-models':
            if (writer) throw new Error('writer_probe_denied');
            if (Object.keys(message.params??{}).length) throw new Error('fixed_synthetic_probe_only');
            result=await this.native.probe();break;
          case 'xeus/oracle-capture': {
            const args=message.params?.arguments;
            if (!writer || !args || typeof args.content!=='string' || args.content.length>4096
                || typeof args.slug!=='string' || !/^cybergym\/episodic\/[a-z0-9-]+$/.test(args.slug)
                || args.type!=='note' || Object.keys(args).some(key=>!['slug','content','type','dry_run'].includes(key))
                || ('dry_run' in args && args.dry_run!==true)) throw new Error('capture_scope_denied');
            result=await this.native.dispatch('capture',args,{remote:true,transport:'http',auth,
              sourceId:auth.sourceId,allowedOps:new Set(['capture']),surface:'starter',surfaceCeiling:'starter',logger:()=>{}});
            break;
          }
          case 'tools/call': {
            if (writer) throw new Error('writer_tools_denied');
            const name = message.params?.name;
            const args = message.params?.arguments ?? {};
            if (!READS.includes(name) || !args || typeof args !== 'object' || Array.isArray(args)
                || ('source_id' in args && args.source_id !== auth.sourceId)
                || ('source_ids' in args) || ('brain_id' in args)) throw new Error('read_scope_denied');
            result = normalizeResult(name, await this.native.dispatch(name, args, {
              remote:true, transport:'http', auth, sourceId:auth.sourceId,
              allowedOps:new Set(READS), surface:'starter', surfaceCeiling:'starter',
              logger:()=>{},
            }));
            break;
          }
          default: throw new Error('method_denied');
        }
        return {jsonrpc:'2.0',id,result};
      });
    } catch {
      return {jsonrpc:'2.0',id,error:{code:-32000,message:'Native authenticated dispatch denied'}};
    }
  }
}

function treeHash(root:string) {
  const entries:string[] = [];
  function visit(relative:string) {
    for (const name of readdirSync(join(root,relative)).sort()) {
      const entry = join(relative,name), stat = lstatSync(join(root,entry));
      if (stat.isSymbolicLink()) throw new Error('package_symlink');
      if (stat.isDirectory()) visit(entry);
      else if (stat.isFile()) entries.push(`${entry}:${sha(readFileSync(join(root,entry)))}`);
    }
  }
  visit('src');
  return sha(entries.join('\n'));
}

export async function loadNative() {
  if (process.env.GBRAIN_HOME !== PROFILE || process.env.GBRAIN_BRAIN_ID) throw new Error('profile_required');
  // Native libraries may log provider errors; never send them into the protocol or evidence.
  console.log = console.info = console.warn = console.error = () => {};
  // Match the dedicated systemd EnvironmentFile without executing shell text.
  // Its historical filename is `env`; GBrain's loader expects `.env`.
  for (const line of readFileSync(`${PROFILE}/.gbrain/env`,'utf8').split('\n')) {
    const match=line.trim().match(/^(OPENAI_API_KEY|VOYAGE_API_KEY)=(.*)$/);
    if (match) {
      const value=match[2].trim();
      process.env[match[1]]=value.replace(/^(["'])(.*)\1$/,'$2');
    }
  }
  process.env.GBRAIN_MODEL_DISCOVERY='0';
  const configApi = await import(`${PACKAGE}/src/core/config.ts`);
  const {createEngine} = await import(`${PACKAGE}/src/core/engine-factory.ts`);
  const gateway = await import(`${PACKAGE}/src/core/ai/gateway.ts`);
  const {buildGatewayConfig} = await import(`${PACKAGE}/src/core/ai/build-gateway-config.ts`);
  const config = configApi.loadConfig();
  if (config?.engine !== 'postgres') throw new Error('dedicated_postgres_required');
  const databaseUrl = new URL(config.database_url);
  const backend_identity_sha256=sha(JSON.stringify({profile:PROFILE,host:databaseUrl.hostname,
    port:databaseUrl.port,database:databaseUrl.pathname,project_user:databaseUrl.username}));
  gateway.configureGateway({...buildGatewayConfig(config),reranker_model:config.reranker_model});
  const engine = await createEngine(configApi.toEngineConfig(config));
  await engine.connect(configApi.toEngineConfig(config));
  await gateway.reconfigureGatewayWithEngine(engine);
  const {sqlQueryForEngine} = await import(`${PACKAGE}/src/core/sql-query.ts`);
  const {GBrainOAuthProvider} = await import(`${PACKAGE}/src/core/oauth-provider.ts`);
  const provider = new GBrainOAuthProvider({sql:sqlQueryForEngine(engine),
    transaction:(fn:any)=>engine.transaction((tx:any)=>fn(sqlQueryForEngine(tx))),dcrDisabled:true});
  return {engine,provider,backend_identity_sha256};
}

async function main() {
  const credentialPath = process.argv[2];
  if (!credentialPath?.startsWith(`${PROFILE}/controller/`)) throw new Error('credential_path_required');
  const stat = lstatSync(credentialPath);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) || stat.uid !== process.getuid!()) {
    throw new Error('credential_permissions_required');
  }
  const credential = JSON.parse(readFileSync(credentialPath,'utf8'));
  const writer=process.argv[3]==='--writer';
  const {engine,provider,backend_identity_sha256} = await loadNative();
  const guard = await import(`${PACKAGE}/src/core/ai/invocation-guard.ts`);
  const {dispatchToolCall} = await import(`${PACKAGE}/src/mcp/dispatch.ts`);
  const {buildToolDefs} = await import(`${PACKAGE}/src/mcp/tool-defs.ts`);
  const {operations} = await import(`${PACKAGE}/src/core/operations.ts`);
  const {VERSION} = await import(`${PACKAGE}/src/version.ts`);
  const gateway = await import(`${PACKAGE}/src/core/ai/gateway.ts`);
  const metadata = {
    source_tree_sha256:treeHash(PACKAGE), runtime_sha256:sha(readFileSync(import.meta.path)),
    native_guard_sha256:sha(readFileSync(`${PACKAGE}/src/core/ai/invocation-guard.ts`)),
    gbrain_version:VERSION, profile:PROFILE, backend_identity_sha256,
  };
  const native_guard_binding_sha256 = sha(JSON.stringify(metadata));
  let token = '', expiresAt = 0;
  const verify = async () => {
    if (Date.now()/1000 >= expiresAt-30) {
      const tokens = await provider.grants.clientCredentials(credential.client_id, credential.client_secret, writer?'read write':'read');
      token = tokens.access_token; expiresAt = Date.now()/1000 + tokens.expires_in;
    }
    return (writer?checkedWriterGrant:checkedGrant)(await provider.verifyAccessToken(token));
  };
  const send = (frame:any) => process.stdout.write(JSON.stringify(frame)+'\n');
  const waits = new Map<string,{resolve:(ok:boolean)=>void,timer:ReturnType<typeof setTimeout>}>();
  const permit = (frame:any) => new Promise<boolean>(resolve => {
    const timer = setTimeout(()=>{waits.delete(frame.id);resolve(false);},30000);
    waits.set(frame.id,{resolve,timer});send(frame);
  });
  const session = new NativeSession({verify,...guard,version:VERSION,mode:writer?'writer':'read',
    metadata:{...metadata,native_guard_binding_sha256},
    tools:buildToolDefs(operations.filter((op:any)=>(writer?['capture']:READS).includes(op.name))),
    probe:async()=>{
      const expansion=await gateway.expand('generic buffer bounds validation');
      const reranking=await gateway.rerank({query:'generic buffer bounds validation',
        documents:['Check the length before reading the buffer.','The sky is blue.'],
        topN:1,model:'voyage:rerank-2.5'});
      return {synthetic_only:true,expansion_count:expansion.length,rerank_count:reranking.length};
    },
    dispatch:(name:string,args:any,opts:any)=>dispatchToolCall(engine,name,args,opts)},permit);
  const lines = createInterface({input:process.stdin,crlfDelay:Infinity});
  let chain = Promise.resolve();
  lines.on('line',line=>{
    if (line.length > 4*1024*1024) {process.exitCode=1;lines.close();return;}
    let message:any;
    try {message=JSON.parse(line);} catch {process.exitCode=1;lines.close();return;}
    if (message.type === 'guard_reply') {
      const pending=waits.get(message.id);
      if (!pending) {process.exitCode=1;lines.close();return;}
      waits.delete(message.id);clearTimeout(pending.timer);pending.resolve(message.ok===true);
    } else {
      chain=chain.then(async()=>{const response=await session.handle(message);if(response)send(response);});
    }
  });
  lines.on('close',()=>{
    for(const pending of waits.values()){clearTimeout(pending.timer);pending.resolve(false);}
    chain.finally(async()=>{await engine.disconnect();process.exit(process.exitCode??0);});
  });
}

if (import.meta.main) main().catch(()=>{process.stderr.write('GBrain controller sidecar startup failed\n');process.exit(1);});
