import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const workflows = fileURLToPath(new URL('../../../.github/workflows/', import.meta.url));
const files = readdirSync(workflows).filter(name => /\.ya?ml$/.test(name));
const publisherName = 'publish-agent-release.yml';

/** Publication must remain a separate, one-time owner action. */
test('only the main-only unified workflow can publish Releases', () => {
  assert.ok(files.includes(publisherName), 'reviewed unified release workflow missing');
  const publishers = files.filter(name => /\bgh release create\b/.test(readFileSync(path.join(workflows, name), 'utf8')));
  assert.deepEqual(publishers, [publisherName], 'unexpected independent Release publisher');
  assert.ok(!files.includes('linux-device-label-release.yml'));
  assert.ok(!files.includes('windows-acceptance-release.yml'));

  const workflow = readFileSync(path.join(workflows, publisherName), 'utf8');
  const triggers = workflow.match(/^on:\n([\s\S]*?)^permissions:/m)?.[1];
  assert.ok(triggers, 'release workflow event gate missing');
  assert.match(triggers, /^  workflow_dispatch:$/m);
  assert.doesNotMatch(triggers, /^  (?:push|pull_request|schedule|workflow_run|workflow_call):/m);
  assert.match(workflow, /if: github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /"\$RELEASE_APPROVAL" != "PUBLISH-\$RELEASE_TAG"/);
  assert.match(workflow, /\.head_branch == "main" and/);
  assert.match(workflow, /\.head_sha == \$sha and/);
  assert.match(workflow, /\.status == "completed" and/);
  assert.match(workflow, /\.conclusion == "success"/);
  assert.match(workflow, /Existing release\/tag may not be overwritten/);
  for (const target of ['linux-x64-glibc', 'linux-arm64-glibc', 'windows-x64']) {
    assert.ok(workflow.includes(`remote-control-agent-$RELEASE_TAG-${target}`));
  }
  assert.match(workflow, /SHA256SUMS\.txt/);
  assert.match(workflow, /gh release create/);
  assert.match(workflow, /gh release download/);
  assert.match(workflow, /sha256sum --check SHA256SUMS\.txt/);
  // GitHub immutable Releases are a repository-level setting; checking only
  // after a draft is made public is too late to prevent a mutable publication.
  const enabledPolicy = 'repos/$GH_REPO/immutable-releases';
  assert.equal(workflow.split(enabledPolicy).length - 1, 2,
    'check repository immutability at initial approval and just before promotion');
  const firstPolicy = workflow.indexOf(enabledPolicy);
  const create = workflow.indexOf('gh release create');
  const publish = workflow.indexOf('gh release edit');
  const secondPolicy = workflow.lastIndexOf(enabledPolicy);
  assert.ok(firstPolicy < create && create < secondPolicy && secondPolicy < publish,
    'no Release may be created or promoted before checking immutable policy');
  assert.equal((workflow.match(/\.enabled == true/g) ?? []).length, 2);
  assert.match(workflow, /\.immutable == true/);
});


test('retired root installer scripts are not advertised distribution files', () => {
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  assert.equal(existsSync(path.join(root,'install-windows.ps1')), false);
  assert.equal(existsSync(path.join(root,'install.sh')), false);
  assert.equal(existsSync(path.join(root,'install.ps1')), true);
});
