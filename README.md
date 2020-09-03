# RSA-FDH

RSA-FDH is a is provably secure blind-signing signature scheme that uses RSA and a [full domain hash](https://en.wikipedia.org/wiki/Full_Domain_Hash).

This project implements a regular signature scheme with Full Domain Hash (FDH) padding.

## Blind signature scheme example

```javascript
const jsbn = require('jsbn');
const bigInt = require('big-integer');
const {FDH_padding} = require("./rsa-fdh");

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

const e = bigInt('65537'); // e = 2^16 + 1
const N = bigInt('531472882770570676887293000203683998395857262924991541446670888838006598797885166924231953798360109794607329237744151603917495201173382697588394565520486479897045440389197396045729909134637979342037950565164286944715296915074941318165306056611723219784320804151038181865705703854418187727984887595020393698712456038519409591918158389776622860787519923190102630707623894247248745831344027403822017518599475726034146758889175085317039374953208595391326037355868651662824427460553225467641095327491840687703263570044634178758049015580565234054421334148471889304047433287697574623716100161497681239470120121798051093986202228003217542188696754447176638745657823509746078165867784692704502582019231109600917470153996285910081586259117198962726726130547959014965905579977295977311082160426110219693228632597177359973352897897423340415941622005125866415622804824990780976808559483720287981583214783913324119411073991583196975920806996613883890633090298669766886012131202640130156013555529900867254163683268680261329440074471283510899115618237917679050056944970901403722137324559140509241664112727384991804907894028818455340243989966152105922086161015279733725729479886644300792405185458040012744056933012184889148841063842605723472941900157');
console.log(`e: ${e}`);
console.log(`N: ${N.toString()}`);

const InitialMessage = 'Hello!';

const PaddedMessage = FDH_padding(InitialMessage, N, 4096);
console.log(`PaddedMessage hex: 0x${PaddedMessage.toString(16)}`);

const r = bigInt.randBetween('1', '5').mod(N);
console.log(`r hex: 0x${r}`);

const d = '23282399963902961889366589919965466215946811753019679196383601963073026613191453899926300248029233489789243362399308165690329565322928753601420278584758482746912697550351491890798946688520158669011260144232825240982614667183120321718305593611734705036861391713347126358186079249371112760227728035846980336435959248769233027730854826083718879920059961540485293082710349884551492275840955531629049426978639467925660853331260534811560188069192393264392588205879104916672550333998326293812618592325389850228055445162246436779443043223397512656518358337126551325082322672215385762922599168240697965091009692530903264807556670680484470229478940107545540835920598906558947901960121419927639247610499138992421409375496421992685721347527087138118721640418340821275729213415264535690693191336998922672043238344531550557349777887236388199934255219772830845326726984447157525409703422748423362819148906352436420831107204592249115128561378232761920339551114561374215401554512094507506349978765112270709835665263857161861822299858997294269998270864303157575035732881330471362077341228729301476533130040454166720399856834620556187156874147234515644344433865712782166068604850278956241690201025638224559129150999995816907370365944270837354719532673';
const MaskedMessage = getMaskedMessage(r, e, N, PaddedMessage);
console.log(`MaskedMessage hex: 0x${MaskedMessage.toString(16)}`);

const MaskedSignature = modPow(MaskedMessage.toString(16), d, N);

const Signature = getSignature(r, N, MaskedSignature);
console.log(`Signature hex: 0x${Signature.toString(16)}`);

const verify = modPow(Signature.toString(16), e, N).equals(PaddedMessage);
console.log(`verify: ${verify}`);
```

## Protocol Description

A full domain hash (FDH) is constructed as follows:

`FDH(𝑀, 𝐼𝑉) = H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 0) ‖ H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 1) ‖ H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 2) ...`

Where:

- 𝑀 is the message
- H is any hash function
- 𝑁 is the signing key's public modulus
- 𝐼𝑉 is a one-byte initialization vector

The message is hashed (along with 𝑁 and 𝐼𝑉 + incrementing suffix) in rounds until the length of the hash is greater than or equal to the length of 𝑁. The hash is truncated as needed to produce the digest 𝐷 with the same length as 𝑁.

𝐷 must also be smaller than 𝑁, so we increment 𝐼𝑉 until we find a 𝐷 that is smaller than 𝑁.

Pseudocode:

```
fn generate_digest(message, public_key):
    fdh = create_fdh(algo=sha256, length=public_key.bitlen())
    iv = 0
    digest = fdh(message, iv)
    while digest.as_int() > public_key.n():
        iv++
        digest = fdh(message, iv)
    return digest
```

The `while` loop finishes within a minimal number of iterations because 𝑁 generally occurs around `(2^bitlen) / 2`.

Two signature schemes are supported:

1. In the regular signature scheme, the signer applies the FDH before signing the message.

2. In the blind-signature scheme, the sender applies the FDH to the message before blinding the resulting digest and sending it to the signer, who signs the blinded digest directly. The signer must not re-use their private keys for encryption outside of the RSA-FDH blind-signature protocol.

Blinding, unblinding, signing and verification are done in the usual way for RSA.

 ## Co-Authors
 
 Maksim Zakharov ([linkedin](https://www.linkedin.com/in/maksim-zakharov/)) ([github](https://github.com/maksim-zakharov))
 Oleg Taraskin ([linkedin](https://www.linkedin.com/in/oleg-taraskin-b9a77996/))
