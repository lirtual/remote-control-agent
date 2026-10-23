import { emitKeypressEvents } from 'node:readline';
import type { ReadStream, WriteStream } from 'node:tty';

/** One explicit local TTY selection; this does not perform owner approval. */
export async function promptInstallMode(
  input: Pick<ReadStream, 'isTTY' | 'isRaw' | 'setRawMode' | 'on' | 'off' | 'resume' | 'pause'> = process.stdin,
  output: Pick<WriteStream, 'isTTY' | 'write'> = process.stdout,
): Promise<'permanent' | 'temporary'> {
  if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== 'function') {
    throw new Error('An interactive TTY is required to select the device mode.');
  }
  const interactiveInput = input as ReadStream;
  const originalRaw = input.isRaw === true;
  const ansi = process.env.NO_COLOR === undefined && process.env.TERM !== 'dumb';
  let index = 0;
  let rendered = false;
  const draw = () => {
    if (rendered && ansi) output.write('\x1b[2A\r\x1b[J');
    output.write((index === 0 ? '> ' : '  ') + '1. Permanent\n');
    output.write((index === 1 ? '> ' : '  ') + '2. Temporary\n');
    rendered = true;
  };
  emitKeypressEvents(interactiveInput);
  input.setRawMode(true);
  input.resume();
  try {
    draw();
    return await new Promise<'permanent' | 'temporary'>((resolve, reject) => {
      let settled = false;
      const closed = () => done(undefined, new Error('Installation cancelled: terminal input closed.'));
      const failed = () => done(undefined, new Error('Installation cancelled: terminal input failed.'));
      const done = (choice?: 'permanent' | 'temporary', err?: Error) => {
        if (settled) return;
        settled = true;
        interactiveInput.off('keypress', keypress);
        interactiveInput.off('end', closed);
        interactiveInput.off('close', closed);
        interactiveInput.off('error', failed);
        if (err) reject(err); else resolve(choice!);
      };
      const keypress = (character: string | undefined, key: { name?: string; ctrl?: boolean }) => {
        if (key?.name === 'escape' || (key?.ctrl && key.name === 'c')) {
          done(undefined, new Error('Installation cancelled.'));
        } else if (character === '1' || character === '2') {
          done(character === '1' ? 'permanent' : 'temporary');
        } else if (key?.name === 'return' || key?.name === 'enter') {
          done(index === 0 ? 'permanent' : 'temporary');
        } else if (key?.name === 'up' || key?.name === 'down') {
          index = 1 - index;
          draw();
        }
      };
      interactiveInput.on('keypress', keypress);
      interactiveInput.once('end', closed);
      interactiveInput.once('close', closed);
      interactiveInput.once('error', failed);
    });
  } finally {
    // resume() keeps a real process.stdin TTY referenced even after selection.
    // Without a matching pause() the installer finishes but Node stays alive.
    try { input.setRawMode(originalRaw); }
    finally { input.pause(); }
  }
}
