/** Existing GitHub Actions OIDC request contract, bounded and nonredirecting. */
export async function runnerOidcToken(url:string,bearer:string,audience:string,
 http:(request:Request)=>Promise<Response>=fetch):Promise<string>{
 const target=new URL(url);
 if(target.protocol!=='https:'||target.username||target.password||target.hash||
    typeof bearer!=='string'||bearer.length<32||audience.length<8||audience.length>256)
   throw Error('Invalid GitHub OIDC request.');
 target.searchParams.set('audience',audience);
 const response=await http(new Request(target,{redirect:'manual',signal:AbortSignal.timeout(8000),
   headers:{authorization:'Bearer '+bearer,accept:'application/json'}}));
 if(response.status!==200||Number(response.headers.get('content-length'))>8192)
   throw Error('GitHub OIDC unavailable.');
 const json=await response.text();
 if(json.length>8192)throw Error('GitHub OIDC response too large.');
 const result=JSON.parse(json) as {value?:unknown};
 if(typeof result.value!=='string'||!/^[-_A-Za-z0-9]+(?:\.[-_A-Za-z0-9]+){2}$/.test(result.value)||
   result.value.length>8192)throw Error('Invalid GitHub OIDC response.');
 return result.value;
}
