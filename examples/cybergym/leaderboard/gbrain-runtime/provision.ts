/** Create or verify ONLY the isolated controller's read-only OAuth client. */
import { mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { loadNative, PACKAGE, PROFILE, SOURCE, READS, checkedGrant, checkedWriterGrant } from './runtime.ts';

const writer=process.argv[2]==='--writer';
const file = `${PROFILE}/controller/${writer?'write':'read'}-client.json`;
const {engine,provider} = await loadNative();
try {
  let credentials:any;
  if (existsSync(file)) credentials = JSON.parse(readFileSync(file,'utf8'));
  else {
    const {resolveGrantProfile} = await import(`${PACKAGE}/src/core/grants/profiles.ts`);
    const {insertClientGrant,grantValidationContext} = await import(`${PACKAGE}/src/core/grants/service.ts`);
    const {validateClientGrant} = await import(`${PACKAGE}/src/core/grants/model.ts`);
    const {sqlQueryForEngine} = await import(`${PACKAGE}/src/core/sql-query.ts`);
    credentials = {client_id:`xeus-cybergym-controller-${randomBytes(8).toString('hex')}`,
      client_secret:randomBytes(32).toString('base64url')};
    const grant = {...resolveGrantProfile({profile:writer?'memory-writer':'memory-reader',sourceId:SOURCE,
      federatedRead:[SOURCE],boundSlugPrefixes:writer?['cybergym/episodic/']:null}),
      clientId:credentials.client_id,clientName:`Xeus CyberGym controller ${writer?'write':'read'} bridge`,
      allowedOperations:writer?['capture']:READS,revision:1,revoked:false};
    validateClientGrant(grant,await grantValidationContext(engine));
    await engine.transaction(async(tx:any)=>insertClientGrant(sqlQueryForEngine(tx),grant,{
      secretHash:createHash('sha256').update(credentials.client_secret).digest('hex'),
      redirectUris:[],grantTypes:['client_credentials'],authMethod:'client_secret_post',
      issuedAt:Math.floor(Date.now()/1000)},'xeus-cybergym-controller-provision'));
    mkdirSync(`${PROFILE}/controller`,{recursive:true,mode:0o700});
    chmodSync(`${PROFILE}/controller`,0o700);
    writeFileSync(file,JSON.stringify(credentials)+'\n',{mode:0o600,flag:'wx'});
  }
  const token = await provider.grants.clientCredentials(credentials.client_id,credentials.client_secret,writer?'read write':'read');
  const auth = (writer?checkedWriterGrant:checkedGrant)(await provider.verifyAccessToken(token.access_token));
  process.stdout.write(JSON.stringify({client_id:auth.clientId,source_id:auth.sourceId,
    source_ids:auth.allowedSources,scopes:auth.scopes,allowed_operations:auth.allowedOperations,
    credential_file:file,grant_revision:auth.grantRevision})+'\n');
} catch {
  process.stderr.write('Dedicated read-client provisioning failed\n');process.exitCode=1;
} finally {await engine.disconnect();}
