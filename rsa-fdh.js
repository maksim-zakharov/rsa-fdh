const bigInt = require('big-integer');
const { sha256 } = require('js-sha256');

function intToByteArray(num) {
    const arr = new Uint8Array([
        (num & 0xff000000) >> 24,
        (num & 0x00ff0000) >> 16,
        (num & 0x0000ff00) >> 8,
        (num & 0x000000ff)
    ]).reverse();
    return arr.buffer;
}

function stringToBytes(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function byteArrayToHexString(data, littleEndian, format) {
    let result = '';
    const v = new Uint8Array(data.slice(0));
    if (littleEndian == null || !littleEndian) {
        v.reverse();
    }
    for (const b of v) {
        const bs = b.toString(16);
        result += (format ? ', (byte)0x' : '') + (bs.length < 2 ? '0' : '') + b.toString(16);
    }
    return result;
}

function FDH_padding(message, N, bitCount) {
    if (bitCount % 256 !== 0) {
        throw new Error('Wrong bit count!!!');
    }

    const blockCount = bitCount / 256;
    const messageBytes = stringToBytes(message);

    const buffer = new ArrayBuffer(512);
    const allBlocks = new Int8Array(buffer);

    for (let i = 0; i < blockCount - 1; i++) {
        const md = sha256.create();
        md.update(intToByteArray(i));
        md.update(messageBytes);
        allBlocks.set(md.digest(), i * 32);
    }

    let j = blockCount - 1;
    let res;

    do {
        const md = sha256.create();
        md.update(intToByteArray(j));
        md.update(messageBytes);
        allBlocks.set(md.digest(), 480);
        const hex = byteArrayToHexString(allBlocks);
        res = bigInt(hex, 16);
        j++;
    } while (N.compareTo(res) <= 0);

    return res;
}

module.exports = {FDH_padding};
