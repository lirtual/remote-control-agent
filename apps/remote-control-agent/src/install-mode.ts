import { emitKeypressEvents } from 'node:readline';
import type { ReadStream, WriteStream } from 'node:tty';

/** One explicit local TTY selection; this does not perform owner approval. */
export async function promptInstallMode(
  input: Pick<ReadStream, 'isTTY' | 'isRaw' | 'setRawMode' | 'on' | 'off' | 'resume'> = process.stdin,
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
    output.write((index === 0 ? '❯' : ' ') + ' 1. 永久\n');
    output.write((index === 1 ? '❯' : ' ') + ' 2. 临时\n');
    rendered = true;
  };
  emitKeypressEvents(interactiveInput);
  input.setRawMode(true);
  input.resume();
  try {
    draw();
    return await new Promise<'permanent' | 'temporary'>((resolve, reject) => {
      const done = (choice?: 'permanent' | 'temporary', err?: Error) => {
        interactiveInput.off('keypress', keypress);
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
    });
  } finally {
    input.setRawMode(originalRaw);
  }
}
