import assert from 'node:assert/strict';
import { test } from 'node:test';
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
  // Both immutable artifacts must advertise owner-one-shot-v1 before Release promotion.
  assert.equal((workflow.match(/\.upgrade_protocol == "owner-one-shot-v1"/g) ?? []).length, 2);
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
