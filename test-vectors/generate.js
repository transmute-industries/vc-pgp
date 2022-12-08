const fs = require('fs');
const openpgp = require('openpgp');


(async ()=>{

  let credential = JSON.parse(fs.readFileSync('../credential.json').toString())

  const k = await openpgp.generateKey({ curve: 'p256',  userIDs: [{ name: credential.issuer }] });
  fs.writeFileSync('./publicKey.pgp', k.publicKey)
  fs.writeFileSync('./privateKey.pgp', k.privateKey)

  const privateKeyArmored = fs.readFileSync('./privateKey.pgp').toString()
  const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored })

  const publicKeyArmored = fs.readFileSync('./publicKey.pgp').toString()
  const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

  // necessary to obtain the verification key
  credential = {
    ...credential,
    proof: {
        type: 'PGPSignature',
        created: new Date().toISOString(),
        proofPurpose: "assertionMethod",
        verificationMethod: credential.issuer + '#key-0'
    }
  }

  const unsignedMessage = await openpgp.createCleartextMessage({ text: JSON.stringify(credential, null, 2) });
  const cleartextMessage = await openpgp.sign({
      message: unsignedMessage, // CleartextMessage or Message object
      signingKeys: privateKey
  });

  fs.writeFileSync('../verifiable-credential.pgp', cleartextMessage)

  const signedMessage = await openpgp.readCleartextMessage({
      cleartextMessage // parse armored message
  });

  const verificationResult = await openpgp.verify({
      message: signedMessage,
      verificationKeys: publicKey
  });
  
  const { verified, keyID } = verificationResult.signatures[0];
  console.log(verificationResult.signatures[0])
  try {
      const data = await verified; // throws on invalid signature
      console.log(data) // true
      console.log('Signed by key id ' + keyID.toHex());
      fs.writeFileSync('../credential.verified.json', verificationResult.data)
  } catch (e) {
      throw new Error('Signature could not be verified: ' + e.message);
  }

})()