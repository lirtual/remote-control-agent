/** Disposable Session identity: never reuse personal enrollment or 24h grants. */
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';

export type SessionPhysicalAttempt = {
  attempt_id: string;
  github_run_id: number;
  github_run_attempt: number;
  workflow_name: 'ubuntu' | 'windows';
};
export type SessionDeviceIdentity = {
  attempt: SessionPhysicalAttempt;
  public_key: string;
  private_key_pem: string;
};
const UUID=/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const NONCE=/^[A-Za-z0-9_-]{16,128}$/;
const PREFIX='remote-control:github-session-enrollment:v1:';

export function assertSessionPhysicalAttempt(input: SessionPhysicalAttempt): void {
  if (!input || typeof input.attempt_id !== 'string' || !UUID.test(input.attempt_id) ||
      !Number.isSafeInteger(input.github_run_id) || input.github_run_id <= 0 ||
      !Number.isSafeInteger(input.github_run_attempt) || input.github_run_attempt <= 0 ||
      (input.workflow_name !== 'ubuntu' && input.workflow_name !== 'windows')) {
    throw Error('Invalid physical Session Attempt.');
  }
}

/** Creates a new Ed25519 identity only; neither pairs nor authorizes it. */
export function newSessionDeviceIdentity(attempt: SessionPhysicalAttempt): SessionDeviceIdentity {
  assertSessionPhysicalAttempt(attempt);
  const pair=generateKeyPairSync('ed25519');
  return {
    attempt:{...attempt},
    public_key:Buffer.from(pair.publicKey.export({type:'spki',format:'der'}) as Buffer).toString('base64'),
    private_key_pem:String(pair.privateKey.export({type:'pkcs8',format:'pem'})),
  };
}

export function validateSessionDeviceIdentity(identity: SessionDeviceIdentity, attempt: SessionPhysicalAttempt): void {
  assertSessionPhysicalAttempt(attempt);
  if (!identity || !identity.attempt ||
      identity.attempt.attempt_id !== attempt.attempt_id ||
      identity.attempt.github_run_id !== attempt.github_run_id ||
      identity.attempt.github_run_attempt !== attempt.github_run_attempt ||
      identity.attempt.workflow_name !== attempt.workflow_name) throw Error('Session identity belongs to another Attempt.');
  const key=createPrivateKey(identity.private_key_pem);
  if (key.asymmetricKeyType!=='ed25519') throw Error('Invalid Session private key.');
  const derived=Buffer.from(createPublicKey(key).export({type:'spki',format:'der'}) as Buffer).toString('base64');
  if (identity.public_key!==derived) throw Error('Session public key mismatch.');
}

/** Signed possession proof binds the one-time nonce, exact physical Attempt and device key. */
export function signSessionEnrollmentNonce(identity: SessionDeviceIdentity, nonce: string): string {
  validateSessionDeviceIdentity(identity,identity.attempt);
  if (typeof nonce!=='string' || !NONCE.test(nonce)) throw Error('Invalid enrollment nonce.');
  const a=identity.attempt;
  const transcript=PREFIX+[a.attempt_id,a.github_run_id,a.github_run_attempt,a.workflow_name,
    identity.public_key,nonce].join(':');
  return Buffer.from(sign(null,Buffer.from(transcript),createPrivateKey(identity.private_key_pem))).toString('base64');
}
