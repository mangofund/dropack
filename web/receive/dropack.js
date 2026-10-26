// Dropack web receiver core: reads .dropack / ZIP files and password-protected
// Dropack packages entirely in the browser. Nothing is uploaded.
//
// Works on any Blob (a File from <input>, or a Blob in tests). Large archives are
// read by random access, so a 30 GB package never has to fit in memory.

const textDecoder = new TextDecoder();
const APPLE_EPOCH_MS = 978307200000; // Swift's JSONEncoder writes dates as seconds since 2001-01-01.

export const ENCRYPTED_MAGIC = 'DROPACKE';
export const ENCRYPTED_HEADER_SIZE = 38;
export const TAG_SIZE = 16;
export const MANIFEST_NAME = 'dropack-manifest.json';

export class DropackError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

const PHOTO_EXT = new Set(['jpg', 'jpeg', 'heic', 'heif', 'png', 'gif', 'tif', 'tiff', 'webp', 'dng', 'raw', 'cr2', 'cr3', 'nef', 'arw', 'avif']);
const VIDEO_EXT = new Set(['mov', 'mp4', 'm4v', 'avi', 'mkv', '3gp', 'hevc', 'webm']);

export function mediaKind(path) {
  const ext = path.split('.').pop().toLowerCase();
  if (PHOTO_EXT.has(ext)) return 'photo';
  if (VIDEO_EXT.has(ext)) return 'video';
  return null;
}

async function readBlob(blob, start, end) {
  return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

/// Byte source over an ordinary file.
export class PlainSource {
  constructor(blob) { this.blob = blob; this.size = blob.size; }
  read(start, end) { return readBlob(this.blob, start, end); }
  async slice(start, end) { return this.blob.slice(start, end); }
}

export async function isEncrypted(blob) {
  if (blob.size < ENCRYPTED_HEADER_SIZE) return false;
  return textDecoder.decode(await readBlob(blob, 0, 8)) === ENCRYPTED_MAGIC;
}

/// Random-access decryption of the format in Dropack/Core/EncryptedPackage.swift:
/// header | AES-256-GCM chunks (ciphertext | 16-byte tag), nonce = prefix || u64 index,
/// AAD = header || final flag. Key = PBKDF2-HMAC-SHA256(password NFC, salt, iterations).
export class EncryptedSource {
  static async open(blob, password, subtle = globalThis.crypto.subtle) {
    if (!password) throw new DropackError('emptyPassword');
    const header = await readBlob(blob, 0, ENCRYPTED_HEADER_SIZE);
    if (header.length !== ENCRYPTED_HEADER_SIZE || textDecoder.decode(header.subarray(0, 8)) !== ENCRYPTED_MAGIC) {
      throw new DropackError('damaged');
    }
    if (header[8] !== 1 || header[9] !== 1) throw new DropackError('unsupportedVersion');
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    const iterations = view.getUint32(10);
    const salt = header.slice(14, 30);
    const chunkSize = view.getUint32(30);
    const noncePrefix = header.slice(34, 38);
    if (iterations < 10000 || iterations > 10000000 || chunkSize < 4096 || chunkSize > 64 * 1024 * 1024) {
      throw new DropackError('damaged');
    }
    const material = await subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    const key = await subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const source = new EncryptedSource(blob, header, key, chunkSize, noncePrefix, subtle);
    try { await source.chunk(0); } catch (error) {
      throw error.code === 'damaged' ? new DropackError('wrongPassword') : error;
    }
    return source;
  }

  constructor(blob, header, key, chunkSize, noncePrefix, subtle) {
    this.blob = blob; this.header = header; this.key = key; this.subtle = subtle;
    this.chunkSize = chunkSize; this.noncePrefix = noncePrefix;
    this.sealedSize = chunkSize + TAG_SIZE;
    const body = blob.size - ENCRYPTED_HEADER_SIZE;
    this.chunkCount = Math.ceil(body / this.sealedSize);
    if (this.chunkCount < 1 || body < this.chunkCount * TAG_SIZE) throw new DropackError('damaged');
    this.size = body - this.chunkCount * TAG_SIZE;
    this.cache = new Map();
  }

  async chunk(index) {
    if (this.cache.has(index)) {
      const value = this.cache.get(index);
      this.cache.delete(index); this.cache.set(index, value);
      return value;
    }
    if (index < 0 || index >= this.chunkCount) throw new DropackError('damaged');
    const start = ENCRYPTED_HEADER_SIZE + index * this.sealedSize;
    const end = Math.min(this.blob.size, start + this.sealedSize);
    const sealed = await readBlob(this.blob, start, end);
    const iv = new Uint8Array(12);
    iv.set(this.noncePrefix, 0);
    new DataView(iv.buffer).setBigUint64(4, BigInt(index));
    const aad = new Uint8Array(this.header.length + 1);
    aad.set(this.header, 0);
    aad[this.header.length] = index === this.chunkCount - 1 ? 1 : 0;
    let plain;
    try {
      plain = new Uint8Array(await this.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, this.key, sealed));
    } catch { throw new DropackError('damaged'); }
    this.cache.set(index, plain);
    if (this.cache.size > 8) this.cache.delete(this.cache.keys().next().value);
    return plain;
  }

  async read(start, end) {
    end = Math.min(end, this.size);
    const out = new Uint8Array(Math.max(0, end - start));
    let position = start;
    while (position < end) {
      const index = Math.floor(position / this.chunkSize);
      const plain = await this.chunk(index);
      const offset = position - index * this.chunkSize;
      const take = Math.min(plain.length - offset, end - position);
      out.set(plain.subarray(offset, offset + take), position - start);
      position += take;
    }
    return out;
  }

  /// Decrypts a range into Blob parts one chunk at a time. Browsers spill large
  /// Blobs to disk, so this stays bounded in memory for big videos.
  async slice(start, end, onProgress = () => {}) {
    const parts = [];
    const step = this.chunkSize;
    for (let position = start; position < end; position += step) {
      parts.push(await this.read(position, Math.min(end, position + step)));
      onProgress((Math.min(end, position + step) - start) / Math.max(1, end - start));
    }
    return new Blob(parts);
  }
}

function u16(bytes, offset) { return bytes[offset] | (bytes[offset + 1] << 8); }
function u32(bytes, offset) { return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0; }
function u64(bytes, offset) {
  const value = u32(bytes, offset) + u32(bytes, offset + 4) * 2 ** 32;
  if (!Number.isSafeInteger(value)) throw new DropackError('damaged');
  return value;
}

/// Minimal ZIP/ZIP64 central-directory reader. Supports stored and deflated entries.
export async function readZip(source) {
  const tailSize = Math.min(source.size, 65557);
  const tail = await source.read(source.size - tailSize, source.size);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (u32(tail, i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new DropackError('notZip');
  let count = u16(tail, eocd + 10);
  let cdSize = u32(tail, eocd + 12);
  let cdOffset = u32(tail, eocd + 16);
  if (u16(tail, eocd + 4) !== 0 || u16(tail, eocd + 6) !== 0) throw new DropackError('multipart');
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const locatorStart = source.size - tailSize + eocd - 20;
    if (locatorStart < 0) throw new DropackError('damaged');
    const locator = await source.read(locatorStart, locatorStart + 20);
    if (u32(locator, 0) !== 0x07064b50) throw new DropackError('damaged');
    const recordOffset = u64(locator, 8);
    const record = await source.read(recordOffset, recordOffset + 56);
    if (u32(record, 0) !== 0x06064b50) throw new DropackError('damaged');
    count = u64(record, 32); cdSize = u64(record, 40); cdOffset = u64(record, 48);
  }
  if (cdOffset + cdSize > source.size) throw new DropackError('damaged');
  const cd = await source.read(cdOffset, cdOffset + cdSize);
  const entries = [];
  let p = 0;
  for (let n = 0; n < count; n++) {
    if (p + 46 > cd.length || u32(cd, p) !== 0x02014b50) throw new DropackError('damaged');
    const flags = u16(cd, p + 8);
    const method = u16(cd, p + 10);
    const crc32 = u32(cd, p + 16);
    let compressedSize = u32(cd, p + 20);
    let size = u32(cd, p + 24);
    const nameLength = u16(cd, p + 28), extraLength = u16(cd, p + 30), commentLength = u16(cd, p + 32);
    let localOffset = u32(cd, p + 42);
    const name = textDecoder.decode(cd.subarray(p + 46, p + 46 + nameLength));
    let e = p + 46 + nameLength;
    const extraEnd = e + extraLength;
    while (e + 4 <= extraEnd) {
      const id = u16(cd, e), length = u16(cd, e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (size === 0xffffffff) { size = u64(cd, q); q += 8; }
        if (compressedSize === 0xffffffff) { compressedSize = u64(cd, q); q += 8; }
        if (localOffset === 0xffffffff) { localOffset = u64(cd, q); q += 8; }
      }
      e += 4 + length;
    }
    if (flags & 1) throw new DropackError('zipEncrypted');
    entries.push({ name, method, crc32, compressedSize, size, localOffset, isDirectory: name.endsWith('/') });
    p = extraEnd + commentLength;
  }
  return new ZipArchive(source, entries);
}

export class ZipArchive {
  constructor(source, entries) {
    this.source = source;
    this.entries = entries;
    this.byName = new Map(entries.map((entry) => [entry.name, entry]));
  }

  async dataOffset(entry) {
    if (entry.dataOffset !== undefined) return entry.dataOffset;
    const local = await this.source.read(entry.localOffset, entry.localOffset + 30);
    if (u32(local, 0) !== 0x04034b50) throw new DropackError('damaged');
    entry.dataOffset = entry.localOffset + 30 + u16(local, 26) + u16(local, 28);
    if (entry.dataOffset + entry.compressedSize > this.source.size) throw new DropackError('damaged');
    return entry.dataOffset;
  }

  /// The entry's original bytes as a Blob, without reading a stored file into memory.
  async blob(entry, onProgress) {
    const start = await this.dataOffset(entry);
    const raw = await this.source.slice(start, start + entry.compressedSize, onProgress);
    if (entry.method === 0) return raw;
    if (entry.method === 8 && typeof DecompressionStream !== 'undefined') {
      const stream = raw.stream().pipeThrough(new DecompressionStream('deflate-raw'));
      return new Response(stream).blob();
    }
    throw new DropackError('unsupportedCompression');
  }

  async text(name) {
    const entry = this.byName.get(name);
    if (!entry) return null;
    return (await this.blob(entry)).text();
  }
}

function appleDate(value) {
  return typeof value === 'number' && Number.isFinite(value) ? new Date(APPLE_EPOCH_MS + value * 1000) : null;
}

function safePath(path) {
  return typeof path === 'string' && path.length > 0 && !path.startsWith('/') && !path.split('/').includes('..');
}

/// Album view model: a Dropack manifest when present, otherwise every media entry.
export async function openAlbum(source) {
  const zip = await readZip(source);
  const manifestText = await zip.text(MANIFEST_NAME);
  if (manifestText) {
    let manifest;
    try { manifest = JSON.parse(manifestText); } catch { throw new DropackError('invalidManifest'); }
    if (manifest.version !== 1 || !Array.isArray(manifest.items) || manifest.items.length === 0) {
      throw new DropackError('invalidManifest');
    }
    const items = manifest.items.map((item) => {
      const resources = [];
      for (const [path, kind, sha256] of [[item.photoPath, 'photo', item.photoSHA256], [item.videoPath, 'video', item.videoSHA256]]) {
        if (path === undefined || path === null) continue;
        const entry = zip.byName.get(path);
        if (!safePath(path) || !entry || mediaKind(path) !== kind) throw new DropackError('invalidManifest');
        resources.push({ kind, entry, sha256: sha256 || null, filename: path.split('/').pop() });
      }
      if (resources.length === 0) throw new DropackError('invalidManifest');
      const preview = item.previewPath ? zip.byName.get(item.previewPath) || null : null;
      return {
        id: item.id, isLivePhoto: Boolean(item.isLivePhoto), creationDate: appleDate(item.creationDate),
        kind: item.photoPath ? 'photo' : 'video', resources, preview,
        byteCount: resources.reduce((sum, resource) => sum + resource.entry.size, 0),
      };
    });
    const album = manifest.album || {};
    return {
      zip, isDropack: true, items,
      title: typeof album.title === 'string' ? album.title : null,
      senderName: typeof album.senderName === 'string' ? album.senderName : null,
      createdAt: appleDate(album.createdAt),
    };
  }
  const items = zip.entries
    .filter((entry) => !entry.isDirectory && mediaKind(entry.name) && !entry.name.split('/').some((part) => part.startsWith('.') || part === '__MACOSX'))
    .map((entry, index) => ({
      id: String(index), isLivePhoto: false, creationDate: null, kind: mediaKind(entry.name), preview: null,
      resources: [{ kind: mediaKind(entry.name), entry, sha256: null, filename: entry.name.split('/').pop() }],
      byteCount: entry.size,
    }));
  if (items.length === 0) throw new DropackError('noMedia');
  return { zip, isDropack: false, items, title: null, senderName: null, createdAt: null };
}

export async function sha256Hex(blob, subtle = globalThis.crypto.subtle) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', await blob.arrayBuffer()));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
