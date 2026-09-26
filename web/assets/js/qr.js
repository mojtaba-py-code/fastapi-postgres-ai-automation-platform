// QR Code Model 2 (ISO/IEC 18004): byte mode, error correction level M, any
// version from 1 to 40. It draws the authenticator-app set-up code in the
// browser, so the TOTP secret is never sent to a third-party QR service.

// GF(256) with the QR code's primitive polynomial x^8 + x^4 + x^3 + x^2 + 1.
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let value = 1;
  for (let index = 0; index < 255; index += 1) {
    EXP[index] = value;
    LOG[value] = index;
    value <<= 1;
    if (value & 0x100) value ^= 0x11d;
  }
  for (let index = 255; index < 512; index += 1) EXP[index] = EXP[index - 255];
}

export function gfMultiply(a, b) {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]];
}

/** The generator polynomial of ``degree``: (x - a^0)(x - a^1)...; highest coefficient first. */
export function generatorPolynomial(degree) {
  let poly = [1];
  for (let root = 0; root < degree; root += 1) {
    const next = new Array(poly.length + 1).fill(0);
    for (let index = 0; index < poly.length; index += 1) {
      next[index] ^= poly[index];
      next[index + 1] ^= gfMultiply(poly[index], EXP[root]);
    }
    poly = next;
  }
  return poly;
}

/** Reed-Solomon error-correction codewords for ``data``. */
export function reedSolomon(data, degree) {
  const generator = generatorPolynomial(degree);
  const remainder = new Array(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ remainder.shift();
    remainder.push(0);
    for (let index = 0; index < degree; index += 1) {
      remainder[index] ^= gfMultiply(generator[index + 1], factor);
    }
  }
  return remainder;
}

// Level M, by version: error-correction codewords per block and number of blocks.
const EC_CODEWORDS = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26,
  26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const EC_BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18,
  20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];

/** Modules that carry codewords (everything but the function patterns). */
export function rawDataModules(version) {
  let modules = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const alignments = Math.floor(version / 7) + 2;
    modules -= (25 * alignments - 10) * alignments - 55;
    if (version >= 7) modules -= 36;
  }
  return modules;
}

export function dataCodewords(version) {
  return Math.floor(rawDataModules(version) / 8) - EC_CODEWORDS[version] * EC_BLOCKS[version];
}

export function alignmentPositions(version) {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  const step = Math.floor((version * 8 + count * 3 + 5) / (count * 4 - 4)) * 2;
  const positions = [6];
  for (let position = size - 7; positions.length < count; position -= step) positions.splice(1, 0, position);
  return positions;
}

/** The 15 format bits for level M and ``mask`` (BCH(15,5), masked with 0x5412). */
export function formatBits(mask) {
  const data = mask; // level M is 0b00
  let remainder = data;
  for (let index = 0; index < 10; index += 1) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
  return ((data << 10) | remainder) ^ 0x5412;
}

/** The 18 version bits (BCH(18,6)), for versions 7 and up. */
export function versionBits(version) {
  let remainder = version;
  for (let index = 0; index < 12; index += 1) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25);
  return (version << 12) | remainder;
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

export function maskApplies(mask, x, y) {
  return MASKS[mask](x, y);
}

function encodeData(bytes, version) {
  const bits = [];
  const push = (value, length) => {
    for (let index = length - 1; index >= 0; index -= 1) bits.push((value >>> index) & 1);
  };
  push(0b0100, 4); // byte mode
  push(bytes.length, version <= 9 ? 8 : 16);
  for (const byte of bytes) push(byte, 8);
  const capacity = dataCodewords(version) * 8;
  push(0, Math.min(4, capacity - bits.length)); // terminator
  push(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) push(pad, 8);
  const codewords = [];
  for (let index = 0; index < bits.length; index += 8) {
    let byte = 0;
    for (let bit = 0; bit < 8; bit += 1) byte = (byte << 1) | bits[index + bit];
    codewords.push(byte);
  }
  return codewords;
}

/** Split into blocks, add each block's error correction, interleave. */
export function interleave(data, version) {
  const blocks = EC_BLOCKS[version];
  const ecLength = EC_CODEWORDS[version];
  const total = Math.floor(rawDataModules(version) / 8);
  const shortBlocks = blocks - (total % blocks);
  const shortLength = Math.floor(total / blocks);
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (let index = 0; index < blocks; index += 1) {
    const length = shortLength - ecLength + (index < shortBlocks ? 0 : 1);
    const block = data.slice(offset, offset + length);
    offset += length;
    dataBlocks.push(block);
    ecBlocks.push(reedSolomon(block, ecLength));
  }
  const result = [];
  for (let index = 0; index <= shortLength - ecLength; index += 1) {
    for (const block of dataBlocks) if (index < block.length) result.push(block[index]);
  }
  for (let index = 0; index < ecLength; index += 1) {
    for (const block of ecBlocks) result.push(block[index]);
  }
  return result;
}

function functionPatterns(version) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const reserved = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => {
    modules[y][x] = dark;
    reserved[y][x] = true;
  };
  for (let index = 0; index < size; index += 1) {
    set(6, index, index % 2 === 0);
    set(index, 6, index % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy += 1) {
      for (let dx = -4; dx <= 4; dx += 1) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        set(x, y, distance !== 2 && distance !== 4);
      }
    }
  }
  const positions = alignmentPositions(version);
  const last = positions.length - 1;
  positions.forEach((cy, row) => {
    positions.forEach((cx, column) => {
      if ((row === 0 && column === 0) || (row === 0 && column === last) || (row === last && column === 0)) return;
      for (let dy = -2; dy <= 2; dy += 1) {
        for (let dx = -2; dx <= 2; dx += 1) set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    });
  });
  drawFormat(modules, reserved, formatBits(0));
  if (version >= 7) {
    const bits = versionBits(version);
    for (let index = 0; index < 18; index += 1) {
      const dark = ((bits >>> index) & 1) !== 0;
      const a = size - 11 + (index % 3);
      const b = Math.floor(index / 3);
      set(a, b, dark);
      set(b, a, dark);
    }
  }
  return { size, modules, reserved };
}

function drawFormat(modules, reserved, bits) {
  const size = modules.length;
  const set = (x, y, index) => {
    modules[y][x] = ((bits >>> index) & 1) !== 0;
    if (reserved) reserved[y][x] = true;
  };
  for (let index = 0; index <= 5; index += 1) set(8, index, index);
  set(8, 7, 6);
  set(8, 8, 7);
  set(7, 8, 8);
  for (let index = 9; index < 15; index += 1) set(14 - index, 8, index);
  for (let index = 0; index < 8; index += 1) set(size - 1 - index, 8, index);
  for (let index = 8; index < 15; index += 1) set(8, size - 15 + index, index);
  modules[size - 8][8] = true; // the dark module
  if (reserved) reserved[size - 8][8] = true;
}

function placeCodewords(modules, reserved, codewords) {
  const size = modules.length;
  let bit = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // the vertical timing pattern
    for (let step = 0; step < size; step += 1) {
      for (let column = 0; column < 2; column += 1) {
        const x = right - column;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - step : step;
        if (reserved[y][x] || bit >= codewords.length * 8) continue;
        modules[y][x] = ((codewords[bit >>> 3] >>> (7 - (bit & 7))) & 1) !== 0;
        bit += 1;
      }
    }
  }
}

/** The ISO 18004 penalty of a masked symbol (lower scans better). */
export function penalty(modules) {
  const size = modules.length;
  let score = 0;
  const lines = [];
  for (let y = 0; y < size; y += 1) lines.push(modules[y]);
  for (let x = 0; x < size; x += 1) lines.push(modules.map((row) => row[x]));
  const finderLike = [
    [true, false, true, true, true, false, true, false, false, false, false],
    [false, false, false, false, true, false, true, true, true, false, true],
  ];
  for (const line of lines) {
    let run = 1;
    for (let index = 1; index <= size; index += 1) {
      if (index < size && line[index] === line[index - 1]) {
        run += 1;
      } else {
        if (run >= 5) score += 3 + (run - 5);
        run = 1;
      }
    }
    for (let index = 0; index + 11 <= size; index += 1) {
      for (const pattern of finderLike) {
        if (pattern.every((dark, offset) => line[index + offset] === dark)) score += 40;
      }
    }
  }
  for (let y = 0; y + 1 < size; y += 1) {
    for (let x = 0; x + 1 < size; x += 1) {
      const colour = modules[y][x];
      if (colour === modules[y][x + 1] && colour === modules[y + 1][x] && colour === modules[y + 1][x + 1]) score += 3;
    }
  }
  let dark = 0;
  for (const row of modules) for (const module of row) if (module) dark += 1;
  const total = size * size;
  score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
  return score;
}

/** The smallest version that holds ``length`` bytes at level M. */
export function versionFor(length) {
  for (let version = 1; version <= 40; version += 1) {
    const needed = 4 + (version <= 9 ? 8 : 16) + length * 8;
    if (needed <= dataCodewords(version) * 8) return version;
  }
  throw new RangeError("Too much data for a QR code");
}

/** Encode ``text`` (UTF-8): a square matrix of booleans, ``true`` for dark. */
export function encodeQr(text) {
  const bytes = Array.from(new TextEncoder().encode(text));
  const version = versionFor(bytes.length);
  const codewords = interleave(encodeData(bytes, version), version);
  const { modules, reserved } = functionPatterns(version);
  placeCodewords(modules, reserved, codewords);
  let best = null;
  for (let mask = 0; mask < 8; mask += 1) {
    const candidate = modules.map((row, y) => row.map((dark, x) => (reserved[y][x] ? dark : dark !== maskApplies(mask, x, y))));
    drawFormat(candidate, null, formatBits(mask));
    const score = penalty(candidate);
    if (!best || score < best.score) best = { score, matrix: candidate };
  }
  return best.matrix;
}
