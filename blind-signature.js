const jsbn = require('jsbn');
const bigInt = require('big-integer');
const {FDH_padding} = require("./rsa-fdh");
const NodeRSA = require('node-rsa');

function getMaskedMessage(r, e, N, PaddedMessage) {
    const jsbnBigR = new jsbn.BigInteger(r.toString());
    const jsbbnN = new jsbn.BigInteger(N.toString());
    const jsbbnE = new jsbn.BigInteger(e.toString());
    const jsbbnPaddedMessage = new jsbn.BigInteger(bigInt(PaddedMessage).toString());

    const MaskedMessage = jsbnBigR.modPow(jsbbnE, jsbbnN).multiply(jsbbnPaddedMessage).mod(jsbbnN);
    return bigInt(MaskedMessage.toString());
}

function modPow(r, e, N) {
    const jsbnBigInt = new jsbn.BigInteger(bigInt(r, 16).toString());
    const jsbbnN = new jsbn.BigInteger(N.toString());
    const jsbbnE = new jsbn.BigInteger(bigInt(e).toString());

    const MaskedMessage = jsbnBigInt.modPow(jsbbnE, jsbbnN);
    return bigInt(MaskedMessage.toString());
}

function getSignature(r, N, MaskedMessage) {
    const jsbnBigInt = new jsbn.BigInteger(r.toString());
    const jsbbnN = new jsbn.BigInteger(N.toString());
    const jsbbnPaddedMessage = new jsbn.BigInteger(bigInt(MaskedMessage).toString());

    const Signature = jsbnBigInt.modInverse(jsbbnN).multiply(jsbbnPaddedMessage).mod(jsbbnN);
    return bigInt(Signature.toString());
}

function keyGeneration({b}) {
    const key = new NodeRSA({b});
    return {
        keyPair: {
            e: bigInt(key.keyPair.e.toString()),
            n: bigInt(key.keyPair.n.toString()),
            d: bigInt(key.keyPair.d.toString())
        }
    };
}

function padded({message, N, b}) {
    return FDH_padding(message, bigInt(N), b)
}

function blind({padded, N, E}) {
    const r = bigInt.randBetween(bigInt.zero, N.add(-1)).mod(N);
    const blinded = getMaskedMessage(r, E, N, padded);

    return {blinded, r};
}

function sign({blinded, key}) {
    return modPow(blinded.toString(16), key.keyPair.d, key.keyPair.n);
}

function unblind({signed, N, r,}) {
    return getSignature(r, N, signed);
}

function verify({unblinded, N, E, padded}) {
    return modPow(unblinded.toString(16), E, N).equals(padded);
}

function verify2({unblinded, key, padded}) {
    return modPow(unblinded.toString(16), key.keyPair.e, key.keyPair.n).equals(padded);
}

const bitCount = 4096;

const InitialMessage = 'Hello!';

// generatedBackendKeys
const key = new NodeRSA({b: bitCount});
const e = bigInt(key.keyPair.e.toString());
const N = bigInt(key.keyPair.n.toString());
const d = bigInt(key.keyPair.d.toString());

// padded
const PaddedMessage = FDH_padding(InitialMessage, N, bitCount);

// blinded
const r = bigInt.randBetween(bigInt.zero, N.add(-1)).mod(N);
const MaskedMessage = getMaskedMessage(r, e, N, PaddedMessage);

// signed
const MaskedSignature = modPow(MaskedMessage.toString(16), d, N);

// unblinded
const Signature = getSignature(r, N, MaskedSignature);

// verify
// const verify = modPow(Signature.toString(16), e, N).equals(PaddedMessage);
// console.log(verify)

module.exports = {keyGeneration, padded, blind, sign, unblind, verify, verify2}
