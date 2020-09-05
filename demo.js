const BlindSignature = require('./blind-signature');

const b = 2048;

const Bob = {
    key: BlindSignature.keyGeneration({ b }), // b: key-length
    blinded: null,
    unblinded: null,
    padded: null,
};

const Alice = {
    message: 'Hello Chaum!',
    N: null,
    E: null,
    r: null,
    padded: null,
    signed: null,
    unblinded: null,
};

// Alice wants Bob to sign a message without revealing it's contents.
// Bob can later verify he did sign the message

console.log('Message:', Alice.message);

// Alice gets N and E variables from Bob's key
Alice.N = Bob.key.keyPair.n.toString();
Alice.E = Bob.key.keyPair.e.toString();

const padded = BlindSignature.padded({
    message: Alice.message,
    N: Alice.N,
    b,
})

Alice.padded = padded;

const { blinded, r } = BlindSignature.blind({
    padded: Alice.padded,
    N: Alice.N,
    E: Alice.E,
}); // Alice blinds message
Alice.r = r;

// Alice sends blinded to Bob
Bob.blinded = blinded;

const signed = BlindSignature.sign({
    blinded: Bob.blinded,
    key: Bob.key,
}); // Bob signs blinded message

// Bob sends signed to Alice
Alice.signed = signed;

const unblinded = BlindSignature.unblind({
    signed: Alice.signed,
    N: Alice.N,
    r: Alice.r,
}); // Alice unblinds
Alice.unblinded = unblinded;

// Alice verifies
const result = BlindSignature.verify({
    unblinded: Alice.unblinded,
    N: Alice.N,
    E: Alice.E,
    padded: Alice.padded,
});
if (result) {
    console.log('Alice: Signatures verify!');
} else {
    console.log('Alice: Invalid signature');
}

// Alice sends Bob unblinded signature and original message
Bob.unblinded = Alice.unblinded;
Bob.message = Alice.message;

// Bob verifies
const result2 = BlindSignature.verify2({
    unblinded: Bob.unblinded,
    key: Bob.key,
    padded: Bob.padded,
});
if (result2) {
    console.log('Bob: Signatures verify!');
} else {
    console.log('Bob: Invalid signature');
}
