// The QR encoder, checked three ways: known answers from ISO/IEC 18004 (and its
// widely published worked examples), a decoder written here from the standard
// that reads every symbol back - format bits, unmasking, the zigzag, the block
// interleaving, the Reed-Solomon syndromes, the byte-mode payload - and the
// structure a scanner looks for (finder and timing patterns).

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  alignmentPositions,
  dataCodewords,
  encodeQr,
  formatBits,
  gfMultiply,
  maskApplies,
  reedSolomon,
  versionBits,
  versionFor,
} from "../../web/assets/js/qr.js";

test("Reed-Solomon: the HELLO WORLD 1-M worked example", () => {
  const data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
  assert.deepEqual(reedSolomon(data, 10), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
});

test("format bits for level M match the standard's table", () => {
  const table = [
    "101010000010010", "101000100100101", "101111001111100", "101101101001011",
    "100010111111001", "100000011001110", "100111110010111", "100101010100000",
  ];
  table.forEach((bits, mask) => assert.equal(formatBits(mask).toString(2).padStart(15, "0"), bits));
});

test("version bits match the standard's table", () => {
  assert.equal(versionBits(7), 0x07c94);
  assert.equal(versionBits(8), 0x085bc);
  assert.equal(versionBits(9), 0x09a99);
  assert.equal(versionBits(10), 0x0a4d3);
  assert.equal(versionBits(40), 0x28c69);
});

test("alignment pattern centres", () => {
  assert.deepEqual(alignmentPositions(1), []);
  assert.deepEqual(alignmentPositions(2), [6, 18]);
  assert.deepEqual(alignmentPositions(7), [6, 22, 38]);
  assert.deepEqual(alignmentPositions(14), [6, 26, 46, 66]);
  assert.deepEqual(alignmentPositions(32), [6, 34, 60, 86, 112, 138]);
  assert.deepEqual(alignmentPositions(40), [6, 30, 58, 86, 114, 142, 170]);
});

test("level-M capacities", () => {
  assert.deepEqual([1, 5, 7, 10, 40].map(dataCodewords), [16, 86, 124, 216, 2334]);
  assert.equal(versionFor(14), 1); // 14 bytes fit version 1-M
  assert.equal(versionFor(15), 2);
  assert.equal(versionFor(122), 7);
  assert.equal(versionFor(123), 8);
  assert.throws(() => versionFor(2332), RangeError);
});

// ------------------------------------------------------------------ decoder

const ALPHA_POWERS = [1];
for (let index = 1; index < 255; index += 1) ALPHA_POWERS.push(gfMultiply(ALPHA_POWERS[index - 1], 2));

function syndromesAreZero(codeword, degree) {
  for (let root = 0; root < degree; root += 1) {
    let value = 0;
    for (const coefficient of codeword) value = gfMultiply(value, ALPHA_POWERS[root]) ^ coefficient;
    if (value !== 0) return false;
  }
  return true;
}

// Level M block structure, as the standard's Table 9 gives it: [blocks, EC per block].
const STRUCTURE = { 1: [1, 10], 2: [1, 16], 3: [1, 26], 4: [2, 18], 5: [2, 24], 6: [4, 16], 7: [4, 18], 8: [4, 22], 9: [5, 22], 10: [5, 26], 13: [9, 22], 14: [9, 24], 15: [10, 24] };

function functionModules(size, version) {
  const reserved = Array.from({ length: size }, () => new Array(size).fill(false));
  const mark = (x, y) => {
    if (x >= 0 && y >= 0 && x < size && y < size) reserved[y][x] = true;
  };
  for (const [x0, y0] of [[0, 0], [size - 8, 0], [0, size - 8]]) {
    for (let y = y0; y < y0 + 8; y += 1) for (let x = x0; x < x0 + 8; x += 1) mark(x, y);
  }
  for (let index = 0; index < size; index += 1) {
    mark(6, index);
    mark(index, 6);
  }
  const centres = alignmentPositions(version);
  for (const cy of centres) {
    for (const cx of centres) {
      const overlapsFinder = (cx < 9 && cy < 9) || (cx > size - 10 && cy < 9) || (cx < 9 && cy > size - 10);
      if (overlapsFinder) continue;
      for (let y = cy - 2; y <= cy + 2; y += 1) for (let x = cx - 2; x <= cx + 2; x += 1) mark(x, y);
    }
  }
  for (let index = 0; index < 9; index += 1) {
    mark(8, index);
    mark(index, 8);
  }
  for (let index = 0; index < 8; index += 1) {
    mark(size - 1 - index, 8);
    mark(8, size - 1 - index);
  }
  if (version >= 7) {
    for (let a = 0; a < 6; a += 1) {
      for (let b = size - 11; b < size - 8; b += 1) {
        mark(a, b);
        mark(b, a);
      }
    }
  }
  return reserved;
}

function decode(matrix) {
  const size = matrix.length;
  const version = (size - 17) / 4;
  assert.ok(Number.isInteger(version) && version >= 1 && version <= 40, "a QR code's size");
  const bit = (x, y) => (matrix[y][x] ? 1 : 0);
  let first = 0;
  const firstPositions = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
  firstPositions.forEach(([x, y], index) => {
    first |= bit(x, y) << index;
  });
  let second = 0;
  for (let index = 0; index < 8; index += 1) second |= bit(size - 1 - index, 8) << index;
  for (let index = 8; index < 15; index += 1) second |= bit(8, size - 15 + index) << index;
  assert.equal(first, second, "both copies of the format information agree");
  const mask = [0, 1, 2, 3, 4, 5, 6, 7].find((candidate) => formatBits(candidate) === first);
  assert.notEqual(mask, undefined, "format information for level M");
  assert.equal(bit(8, size - 8), 1, "the dark module");

  const reserved = functionModules(size, version);
  const bits = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let step = 0; step < size; step += 1) {
      const y = upward ? size - 1 - step : step;
      for (const x of [right, right - 1]) {
        if (reserved[y][x]) continue;
        bits.push(bit(x, y) ^ (maskApplies(mask, x, y) ? 1 : 0));
      }
    }
  }
  const codewords = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    codewords.push(bits.slice(index, index + 8).reduce((byte, value) => (byte << 1) | value, 0));
  }
  const [blocks, ecLength] = STRUCTURE[version];
  const dataTotal = dataCodewords(version);
  const shortData = Math.floor(dataTotal / blocks);
  const longBlocks = dataTotal % blocks;
  const lengths = Array.from({ length: blocks }, (_, index) => shortData + (index >= blocks - longBlocks ? 1 : 0));
  const dataBlocks = lengths.map(() => []);
  let cursor = 0;
  for (let column = 0; column < shortData + 1; column += 1) {
    dataBlocks.forEach((block, index) => {
      if (column < lengths[index]) block.push(codewords[cursor++]);
    });
  }
  const ecBlocks = lengths.map(() => []);
  for (let column = 0; column < ecLength; column += 1) ecBlocks.forEach((block) => block.push(codewords[cursor++]));
  dataBlocks.forEach((block, index) => {
    assert.ok(syndromesAreZero([...block, ...ecBlocks[index]], ecLength), `block ${index} is a Reed-Solomon codeword`);
  });
  const stream = dataBlocks.flat().flatMap((byte) => Array.from({ length: 8 }, (_, index) => (byte >>> (7 - index)) & 1));
  const read = (() => {
    let position = 0;
    return (length) => {
      let value = 0;
      for (let index = 0; index < length; index += 1) value = (value << 1) | stream[position++];
      return value;
    };
  })();
  assert.equal(read(4), 0b0100, "byte mode");
  const count = read(version <= 9 ? 8 : 16);
  const bytes = Array.from({ length: count }, () => read(8));
  return { version, mask, text: new TextDecoder().decode(new Uint8Array(bytes)) };
}

function assertFinder(matrix, x0, y0) {
  for (let y = 0; y < 7; y += 1) {
    for (let x = 0; x < 7; x += 1) {
      const ring = Math.max(Math.abs(x - 3), Math.abs(y - 3));
      assert.equal(matrix[y0 + y][x0 + x], ring !== 2, `finder module ${x0 + x},${y0 + y}`);
    }
  }
}

const SAMPLES = [
  "",
  "a",
  "HELLO WORLD",
  "Zürich ✓ – ünïcödé",
  "otpauth://totp/NexusFlow%20AI:alice%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=NexusFlow%20AI&algorithm=SHA1&digits=6&period=30",
  "x".repeat(122), // the last length that fits version 7
  "y".repeat(123),
  "z".repeat(213), // version 10: 16-bit count, five blocks
  "long block interleaving ".repeat(14), // version 14 at level M: short and long blocks
];

for (const text of SAMPLES) {
  test(`round trip: ${JSON.stringify(text.slice(0, 32))}${text.length > 32 ? "…" : ""} (${text.length})`, () => {
    const matrix = encodeQr(text);
    const size = matrix.length;
    assertFinder(matrix, 0, 0);
    assertFinder(matrix, size - 7, 0);
    assertFinder(matrix, 0, size - 7);
    for (let index = 8; index < size - 8; index += 1) {
      assert.equal(matrix[6][index], index % 2 === 0, "horizontal timing pattern");
      assert.equal(matrix[index][6], index % 2 === 0, "vertical timing pattern");
    }
    const decoded = decode(matrix);
    assert.equal(decoded.text, text);
    assert.equal(decoded.version, versionFor(new TextEncoder().encode(text).length));
  });
}

test("the version information is readable in both corners", () => {
  const matrix = encodeQr("v".repeat(150)); // version 8
  const size = matrix.length;
  let topRight = 0;
  let bottomLeft = 0;
  for (let index = 0; index < 18; index += 1) {
    const a = size - 11 + (index % 3);
    const b = Math.floor(index / 3);
    topRight |= (matrix[b][a] ? 1 : 0) << index;
    bottomLeft |= (matrix[a][b] ? 1 : 0) << index;
  }
  assert.equal(topRight, versionBits(8));
  assert.equal(bottomLeft, versionBits(8));
});
