Future keytest() async {
    String foo = ‘Hello world’;
    List<int> message = utf8.encode(foo);
    print(message);
    var random = new Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPairFromSeed(seeds);
    // Sign
    final signature = await algorithm.sign(
      message,
      keyPair: keyPair,
    );
    print(‘Signature: ${signature.bytes}’);
    print(‘Public key: ${signature.publicKey}’);
    print(‘signature base58: ${Base58Encode(signature.bytes)}’);
    var encodedPub = Base58Encode((await keyPair.extractPublicKey()).bytes);
    var encodedPriv = Base58Encode((await keyPair.extractPrivateKeyBytes()));
    print(‘test: ${(await keyPair.extractPublicKey())}’);
    print(‘Pub: ${encodedPub}’);
    print(‘priv: ${encodedPriv}’);
    // Verify signature
    final isSignatureCorrect = await algorithm.verify(
      message,
      signature: signature,
    );
    print(‘Correct signature: $isSignatureCorrect’);
}