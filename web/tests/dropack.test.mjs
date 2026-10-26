// Run: python3 web/tests/make_fixtures.py <dir> && DROPACK_FIXTURES=<dir> node --test web/tests
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { EncryptedSource, PlainSource, isEncrypted, openAlbum, sha256Hex } from '../receive/dropack.js';

const dir = process.env.DROPACK_FIXTURES;
const file = (name) => new Blob([readFileSync(join(dir, name))]);
const expected = JSON.parse(readFileSync(join(dir, 'album.json'), 'utf8'));

async function checkAlbum(album) {
  assert.equal(album.isDropack, true);
  assert.equal(album.title, '京都 · 2026 秋');
  assert.equal(album.senderName, 'PRO.X');
  assert.equal(album.items.length, 2);
  const [live, video] = album.items;
  assert.equal(live.isLivePhoto, true);
  assert.equal(live.resources.length, 2);
  assert.ok(live.preview);
  assert.equal(live.creationDate.toISOString(), new Date(1792000000 * 1000).toISOString());
  assert.equal(video.kind, 'video');
  for (const [index, item] of album.items.entries()) {
    for (const resource of item.resources) {
      const blob = await album.zip.blob(resource.entry);
      assert.equal(blob.size, resource.entry.size);
      const want = resource.kind === 'photo' ? expected.items[index].photoSHA256 : expected.items[index].videoSHA256;
      assert.equal(await sha256Hex(blob), want);
    }
  }
}

test('reads a ZIP32 Dropack album with its manifest', async () => {
  const blob = file('album.dropack');
  assert.equal(await isEncrypted(blob), false);
  await checkAlbum(await openAlbum(new PlainSource(blob)));
});

test('reads ZIP64 records', async () => {
  await checkAlbum(await openAlbum(new PlainSource(file('album64.dropack'))));
});

test('decrypts a password-protected package by random access', async () => {
  const blob = file('album-locked.dropack');
  assert.equal(await isEncrypted(blob), true);
  await assert.rejects(EncryptedSource.open(blob, 'wrong-password'), { code: 'wrongPassword' });
  const source = await EncryptedSource.open(blob, 'dropack-test');
  assert.equal(source.size, file('album.dropack').size);
  await checkAlbum(await openAlbum(source));
});

test('detects tampering inside an encrypted package', async () => {
  const bytes = new Uint8Array(readFileSync(join(dir, 'album-locked.dropack')));
  bytes[38 + 4112 + 100] ^= 1; // second chunk
  const source = await EncryptedSource.open(new Blob([bytes]), 'dropack-test');
  await assert.rejects(source.read(4096, 4200), { code: 'damaged' });
});

test('lists media from an ordinary ZIP, skipping metadata files', async () => {
  const album = await openAlbum(new PlainSource(file('plain.zip')));
  assert.equal(album.isDropack, false);
  assert.deepEqual(album.items.map((item) => item.resources[0].filename), ['a.jpg', 'b.mp4']);
  const photo = await album.zip.blob(album.items[0].resources[0].entry);
  assert.equal(photo.size, 3002); // deflated entry inflates back
});
