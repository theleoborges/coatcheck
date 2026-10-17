import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ConfigError } from '@coatcheck/core';
import createProvider, { createFileProvider, parseSecretsFile } from './file.js';

let dir: string;
let file: string;

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'coatcheck-file-'));
  file = path.join(dir, 'secrets.json');
  await fs.writeFile(file, JSON.stringify({ secrets: { 'github-token': 'gh', 'Api.Key_2': 'k' }, shared: { 'bb-key': 'bb' } }));
});
afterEach(async () => { await fs.rm(dir, { recursive: true, force: true }); });

describe('file provider', () => {
  it('requires COATCHECK_SECRETS_FILE', async () => {
    await expect(createProvider({ env: {} })).rejects.toThrow(/COATCHECK_SECRETS_FILE is required/);
  });

  it('fails startup on a missing or malformed file', async () => {
    await expect(createFileProvider({ path: path.join(dir, 'nope.json') })).rejects.toThrow(/ENOENT/);
    await fs.writeFile(file, '{"secrets": {"a": 1}}');
    await expect(createFileProvider({ path: file })).rejects.toThrow(ConfigError);
  });

  it('reads per-agent and shared secrets with core name rules', async () => {
    const p = await createProvider({ env: { COATCHECK_SECRETS_FILE: file } });
    expect(p.name).toBe('file');
    expect(await p.secrets.get('github-token')).toEqual({ value: 'gh' });
    expect(await p.secrets.get('Api.Key_2')).toEqual({ value: 'k' });
    expect(await p.secrets.get('toString')).toBeNull();
    expect(await p.secrets.exists('bb-key')).toBe(false);
    expect(await p.secrets.list()).toEqual(['Api.Key_2', 'github-token']);
    expect(await p.shared!.get('bb-key')).toEqual({ value: 'bb' });
  });

  it('put writes atomically through a temp file and keeps the shared section', async () => {
    const p = await createFileProvider({ path: file });
    await Promise.all([p.secrets.put!('a', '1'), p.secrets.put!('b', '2'), p.secrets.put!('github-token', 'new')]);
    const onDisk = JSON.parse(await fs.readFile(file, 'utf8'));
    expect(onDisk).toEqual({ secrets: { 'github-token': 'new', 'Api.Key_2': 'k', a: '1', b: '2' }, shared: { 'bb-key': 'bb' } });
    expect(await fs.readdir(dir)).toEqual(['secrets.json']); // no temp files left behind
    expect((await fs.stat(file)).mode & 0o777).toBe(0o600);
  });

  it('a failed write leaves the original file intact', async () => {
    const p = await createFileProvider({ path: file });
    const before = await fs.readFile(file, 'utf8');
    await fs.chmod(dir, 0o500); // directory not writable: the temp file can't be created
    try {
      await expect(p.secrets.put!('a', '1')).rejects.toThrow();
    } finally {
      await fs.chmod(dir, 0o700);
    }
    expect(await fs.readFile(file, 'utf8')).toBe(before);
  });

  it('parse errors never include values', () => {
    expect(() => parseSecretsFile('{"secrets": {"a": {"nested": "sekrit"}}}', 'f')).toThrow(/secrets\.a must be a string/);
    try { parseSecretsFile('{"secrets": {"a": {"nested": "sekrit"}}}', 'f'); } catch (e) { expect(String(e)).not.toContain('sekrit'); }
    expect(() => parseSecretsFile('{"extra": {}}', 'f')).toThrow(/unknown key/);
    expect(() => parseSecretsFile('[]', 'f')).toThrow(ConfigError);
  });
});
