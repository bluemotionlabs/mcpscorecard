import { describe, expect, it } from 'vitest';
import { iterateTar, readCapped, readString, computeToolSchemaHash } from './checks/capabilities.js';

function simpleTar(name: string, data: Uint8Array): Uint8Array {
  const headerSize = 512;
  const paddedSize = Math.ceil(data.length / headerSize) * headerSize;
  const tar = new Uint8Array(headerSize + paddedSize + (2 * headerSize));

  const enc = new TextEncoder();
  const nameBytes = enc.encode(name);
  tar.set(nameBytes.subarray(0, Math.min(nameBytes.length, 100)), 0);

  const sizeOctal = data.length.toString(8).padStart(11, '0');
  tar.set(enc.encode(sizeOctal + ' '), 124);

  tar.set(data, headerSize);

  return tar;
}

describe('iterateTar', () => {
  it('extracts a single file from a minimal tar', () => {
    const content = new TextEncoder().encode('hello world');
    const tar = simpleTar('hello.txt', content);
    const entries = [...iterateTar(tar)];
    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe('hello.txt');
    expect(new TextDecoder().decode(entries[0]!.data)).toBe('hello world');
  });

  it('extracts multiple files', () => {
    const a = new TextEncoder().encode('AAA');
    const b = new TextEncoder().encode('BBBB');
    const headerSize = 512;
    const padA = Math.ceil(a.length / headerSize) * headerSize;
    const total = headerSize + padA + headerSize + Math.ceil(b.length / headerSize) * headerSize + (2 * headerSize);
    const tar = new Uint8Array(total);

    const enc = new TextEncoder();
    tar.set(enc.encode('a.txt').subarray(0, 5), 0);
    tar.set(enc.encode(a.length.toString(8).padStart(11, '0') + ' '), 124);
    tar.set(a, headerSize);

    const offB = headerSize + padA;
    tar.set(enc.encode('b.txt').subarray(0, 5), offB);
    tar.set(enc.encode(b.length.toString(8).padStart(11, '0') + ' '), offB + 124);
    tar.set(b, offB + headerSize);

    const entries = [...iterateTar(tar)];
    expect(entries).toHaveLength(2);
    expect(entries[0]!.name).toBe('a.txt');
    expect(entries[1]!.name).toBe('b.txt');
  });

  it('returns empty for an empty tar (all zeros)', () => {
    const tar = new Uint8Array(512);
    const entries = [...iterateTar(tar)];
    expect(entries).toHaveLength(0);
  });

  it('skips directory entries (type 5)', () => {
    const name = 'mydir/';
    const headerSize = 512;
    const tar = new Uint8Array(headerSize + headerSize * 2);

    const enc = new TextEncoder();
    tar.set(enc.encode(name).subarray(0, 6), 0);
    tar.set(enc.encode('0'.padStart(11, '0') + ' '), 124);
    tar[156] = '5'.charCodeAt(0);

    const entries = [...iterateTar(tar)];
    expect(entries).toHaveLength(0);
  });
});

describe('readString', () => {
  it('reads a null-terminated string', () => {
    const bytes = new TextEncoder().encode('hello\0world');
    expect(readString(bytes, 0, 11)).toBe('hello');
  });

  it('reads a full-width string with no null', () => {
    const bytes = new TextEncoder().encode('hello');
    expect(readString(bytes, 0, 5)).toBe('hello');
  });

  it('reads empty for zero-length', () => {
    const bytes = new Uint8Array(0);
    expect(readString(bytes, 0, 0)).toBe('');
  });
});

describe('readCapped', () => {
  function makeStream(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
    let i = 0;
    return new ReadableStream({
      pull(controller) {
        if (i < chunks.length) {
          controller.enqueue(chunks[i++]!);
        } else {
          controller.close();
        }
      },
    });
  }

  it('reads an under-cap stream', async () => {
    const data = new Uint8Array([1, 2, 3]);
    const result = await readCapped(makeStream([data]), 100);
    expect(result).toBeDefined();
    expect([...result!]).toEqual([1, 2, 3]);
  });

  it('caps at the limit', async () => {
    const data = new Uint8Array(1000).fill(1);
    const result = await readCapped(makeStream([data]), 500);
    expect(result).toBeDefined();
    expect(result!.length).toBeLessThanOrEqual(500);
  });

  it('returns empty array for empty stream', async () => {
    const result = await readCapped(makeStream([]), 100);
    expect(result).toBeDefined();
    expect(result!.length).toBe(0);
  });
});

describe('computeToolSchemaHash', () => {
  it('is stable when inputSchema keys are in different order', async () => {
    const toolsA = [{ name: 'a', description: 'desc', inputSchema: { type: 'object', properties: { x: { type: 'string' }, y: { type: 'number' } } } }];
    const toolsB = [{ name: 'a', description: 'desc', inputSchema: { type: 'object', properties: { y: { type: 'number' }, x: { type: 'string' } } } }];
    expect(await computeToolSchemaHash(toolsA)).toBe(await computeToolSchemaHash(toolsB));
  });
});
