import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const workflows = fileURLToPath(new URL('../../../.github/workflows/', import.meta.url));
const files = readdirSync(workflows).filter(name => /\.ya?ml$/.test(name));
const publisherName = 'publish-agent-release.yml';

/** Only one reviewed, pinned version is automatically published on main. */
test('only the main-only unified workflow can publish Releases', () => {
  assert.ok(files.includes(publisherName), 'reviewed unified release workflow missing');
  const publishers = files.filter(name => /\bgh release create\b/.test(readFileSync(path.join(workflows, name), 'utf8')));
  assert.deepEqual(publishers, [publisherName], 'unexpected independent Release publisher');
  assert.ok(!files.includes('linux-device-label-release.yml'));
  assert.ok(!files.includes('windows-acceptance-release.yml'));

  const workflow = readFileSync(path.join(workflows, publisherName), 'utf8');
  const triggers = workflow.match(/^on:\n([\s\S]*?)^permissions:/m)?.[1];
  assert.ok(triggers, 'release workflow event gate missing');
  assert.match(triggers, /^  push:$/m);
  assert.match(triggers, /^    branches: \[main\]$/m);
  assert.match(triggers, /^      - '\.github\/release-pins\/\*\.json'$/m);
  assert.match(triggers, /^  workflow_dispatch:$/m);
  assert.doesNotMatch(triggers, /^  (?:pull_request|schedule|workflow_run|workflow_call):/m);
  assert.match(workflow, /if: github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /A main push must change exactly one release pin/);
  assert.match(workflow, /git diff --name-only "\$BASE_SHA" "\$GITHUB_SHA"/);
  assert.match(workflow, /printf 'RELEASE_TAG=%s/);
  assert.match(workflow, /\.head_branch == "main" and/);
  assert.match(workflow, /\.head_sha == \$sha and/);
  assert.match(workflow, /\.status == "completed" and/);
  assert.match(workflow, /\.conclusion == "success"/);
  assert.match(workflow, /Existing release\/tag may not be overwritten/);
  for (const target of ['linux-x64-glibc', 'linux-arm64-glibc', 'windows-x64']) {
    assert.ok(workflow.includes(`remote-control-agent-$RELEASE_TAG-${target}`));
  }
  // New immutable Releases must not advertise the retired remote-upgrade protocol.
  assert.equal((workflow.match(/\.upgrade_protocol == null/g) ?? []).length, 3);
  assert.equal((workflow.match(/\.upgrade_profile == "paired-full-v1"/g) ?? []).length, 2);
  assert.match(workflow, /unzip -p "\$archive" bundle\.json \| jq -e/);
  assert.match(workflow, /tar -xzOf "\$archive" bundle\.json \| jq -e/);
  assert.match(workflow, /SHA256SUMS\.txt/);
  assert.match(workflow, /gh release create/);
  assert.match(workflow, /gh release download/);
  assert.match(workflow, /sha256sum --check SHA256SUMS\.txt/);
  // Existing tags remain protected, artifacts must be checked before promotion.
  assert.match(workflow, /gh release view "\$RELEASE_TAG"/);
  assert.match(workflow, /\.tag_name == \$tag and \.draft == false/);
  assert.match(workflow, /\.object\.sha == \$sha/);
  assert.doesNotMatch(workflow, /RELEASE_POLICY_READ_TOKEN|immutable-releases|\.immutable == true/);
  assert.doesNotMatch(workflow, /RELEASE_APPROVAL|PUBLISH-\$RELEASE_TAG/);

});


test('retired root installer scripts are not advertised distribution files', () => {
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  assert.equal(existsSync(path.join(root,'install-windows.ps1')), false);
  assert.equal(existsSync(path.join(root,'install.sh')), false);
  assert.equal(existsSync(path.join(root,'install.ps1')), true);
});

/** #662: the existing release pin gate supports old three-platform versions
 * unchanged and five exact candidates only after separate owner release approval.
 * Missing jq locally skips the dynamic check; native Ubuntu CI has jq. */
test('reviewed three- and five-platform pin contracts are fail-closed', {
  skip: !!spawnSync('jq',['--version'],{encoding:'utf8'}).error,
}, () => {
  const root=fileURLToPath(new URL('../../../',import.meta.url));
  const workflow=readFileSync(path.join(workflows,publisherName),'utf8');
  const anchor=`jq -e --arg tag "$RELEASE_TAG" '`;
  const start=workflow.indexOf(anchor);
  const stop=workflow.indexOf(`' "$pin" >/dev/null`,start);
  const filter=start>=0 && stop>start ? workflow.slice(start+anchor.length,stop) : null;
  assert.ok(filter,'release pin jq gate missing');
  const check=(pin,expected)=> {
    const result=spawnSync('jq',['-e','--arg','tag',pin.tag,filter],{
      input:JSON.stringify(pin),encoding:'utf8',timeout:5000,
    });
    assert.equal(result.status,expected?0:1,
      'pin acceptance mismatch: '+(result.stderr??'').slice(0,500));
  };
  const old=JSON.parse(readFileSync(path.join(root,'.github/release-pins/v0.1.48.json'),'utf8'));
  check(old,true);
  const tag='v0.1.99-test.1';
  const pin={...old,tag,macos_script_sha256:'e'.repeat(64),
    assets:[
      ...old.assets.map(asset=>({
        ...asset,
        name:asset.name.replaceAll(old.tag,tag),
        artifact:asset.artifact.replaceAll(old.tag,tag),
      })),
      ...['arm64','x64'].map((arch,index)=>({
        target:'darwin-'+arch,
        artifact:tag+'-darwin-'+arch,
        name:'remote-control-agent-'+tag+'-darwin-'+arch+'.tar.gz',
        sha256:(index?'d':'c').repeat(64),
      })),
    ]};
  check(pin,true);
  check({...pin,macos_script_sha256:undefined},false);
  check({...pin,assets:pin.assets.slice(0,4)},false);
  check({...pin,assets:[...pin.assets].reverse()},false);
  check({...pin,assets:pin.assets.map((a,i)=>i===4?{...a,artifact:'wrong'}:a)},false);
  check({...pin,assets:pin.assets.map((a,i)=>i===3?{...a,sha256:'z'.repeat(64)}:a)},false);
  check({...old,assets:[...old.assets,pin.assets[3]]},false);
});

test('five-platform assets never publish from candidate CI or source-only merge',()=>{
  const workflow=readFileSync(path.join(workflows,publisherName),'utf8');
  for(const expected of [
    "if: github.ref == 'refs/heads/main'",
    '.assets | length == 5',
    '.macos_script_sha256',
    'darwin-arm64','darwin-x64',
    'gh release create "$RELEASE_TAG"',
    'assets+=(',
    'source_digest="$(git show',
    'candidate_profile == "darwin-permanent-local-v1"',
    'native_supervisor == "darwin-owned-group-v1"',
    'upgrade_profile == null',
    'count+1',
  ]) assert.ok(workflow.includes(expected), 'missing reviewed gate: '+expected);
});
