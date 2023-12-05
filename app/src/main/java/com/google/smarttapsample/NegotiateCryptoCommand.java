/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.smarttapsample;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Class encapsulates the generation of the `negotiate smart tap secure sessions` command
 * https://developers.google.com/wallet/smart-tap/reference/apdu-commands/negotiate-secure-sessions
 */
class NegotiateCryptoCommand {

  /**
   * --- spoZebra BEGIN
   * Collector ID updated: 12345678
   */
  //static final byte[] COLLECTOR_ID = new byte[]{(byte) 0x01, (byte) 0x33, (byte) 0xEE, (byte) 0x80};
  static final byte[] COLLECTOR_ID = new byte[]{(byte) 0x00 , (byte) 0xBC, (byte) 0x61, (byte) 0x4E};

  /**
   * --- spoZebra END ---
   */

  // Private key is hardcoded for this sample app
  /**
   * --- spoZebra BEGIN ---
   * Private key updated
   */

  /*private static final String LONG_TERM_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\n"
          + "MHcCAQEEIIJtF+UHZ7FlsOTZ4zL40dHiAiQoT7Ta8eUKAyRucHl9oAoGCCqGSM49\n"
          + "AwEHoUQDQgAEchyXj869zfmKhRi9xP7f2AK07kEo4lE7ZlWTN14jh4YBTny+hRGR\n"
          + "XcUzevV9zSSPJlPHpqqu5pEwlv1xyFvE1w==\n"
          + "-----END EC PRIVATE KEY-----\n";*/
  private static final String LONG_TERM_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\n" +
          "MHcCAQEEIIJtF+UHZ7FlsOTZ4zL40dHiAiQoT7Ta8eUKAyRucHl9oAoGCCqGSM49\n" +
          "AwEHoUQDQgAEchyXj869zfmKhRi9xP7f2AK07kEo4lE7ZlWTN14jh4YBTny+hRGR\n" +
          "XcUzevV9zSSPJlPHpqqu5pEwlv1xyFvE1w==\n" +
          "-----END EC PRIVATE KEY-----\n";
  /**
   * --- spoZebra END ---
   */

  /**
   * --- spoZebra BEGIN ---
   * Key Version ID updated
   */
  /*private static final byte[] LONG_TERM_PRIVATE_KEY_VERSION = new byte[]{(byte) 0x00, (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01};*/
  private static final byte[] LONG_TERM_PRIVATE_KEY_VERSION = new byte[]{(byte) 0x00, (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01};
  /**
   * --- spoZebra END ---
   */

  private static final byte[] COMMAND_PREFIX = new byte[]{(byte) 0x90, (byte) 0x53, (byte) 0x00,
      (byte) 0x00};

  byte[] sessionId;
  NdefRecord collectorIdRecord;
  byte[] terminalNonce;
  private ECPublicKey terminalEphemeralPublicKey;
  byte[] terminalEphemeralPublicKeyCompressed;
  PrivateKey terminalEphemeralPrivateKey;
  byte[] signedData;
  private NdefRecord negotiateCryptoRecord;

  /**
   * Constructor for the class
   *
   * @param mobileDeviceNonce Mobile device nonce
   */
  NegotiateCryptoCommand(byte[] mobileDeviceNonce) throws Exception {
    try {
      // Create the needed NDEF records
      NdefRecord sessionRecord = createSessionRecord();
      NdefRecord signatureRecord = createSignatureRecord(mobileDeviceNonce);
      createCollectorIdRecord();
      NdefRecord cryptoParamsRecord = createCryptoParamsRecord(signatureRecord);
      createNegotiateCryptoRecord(sessionRecord, cryptoParamsRecord);
    } catch (Exception e) {
      throw new SmartTapException(
          "Problem creating `negotiate smart tap secure sessions` command: " + e);
    }
  }

  /**
   * Creates the negotiate request NDEF record
   *
   * @param sessionRecord Session NDEF record
   * @param cryptoParamsRecord Cryptography params NDEF record
   */
  private void createNegotiateCryptoRecord(NdefRecord sessionRecord, NdefRecord cryptoParamsRecord)
      throws IOException {
    negotiateCryptoRecord = new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x6E, (byte) 0x67, (byte) 0x72}, // `ngr` in byte-array form
        null,
        Utils.concatenateByteArrays(
            new byte[]{(byte) 0x00, (byte) 0x01}, // Live auth byte
            (new NdefMessage(sessionRecord, cryptoParamsRecord)).toByteArray()));
  }

  /**
   * Creates the cryptography params NDEF record
   *
   * @param signatureRecord Signature NDEF record
   * @return Cryptography params NDEF record
   */
  private NdefRecord createCryptoParamsRecord(NdefRecord signatureRecord) throws IOException {
    return new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x63, (byte) 0x70, (byte) 0x72}, // `cpr` in byte-array form
        null,
        Utils.concatenateByteArrays(
            terminalNonce,
            new byte[]{(byte) 0x01}, // Live auth byte
            terminalEphemeralPublicKeyCompressed,
            LONG_TERM_PRIVATE_KEY_VERSION,
            (new NdefMessage(signatureRecord, collectorIdRecord)).toByteArray()));
  }

  /**
   * Creates the Collector ID ndef record
   */
  private void createCollectorIdRecord() throws IOException {
    collectorIdRecord = new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x63, (byte) 0x6c, (byte) 0x64}, // `cld` in byte-array form
        null,
        Utils.concatenateByteArrays(
            new byte[]{(byte) 0x04}, // Payload format byte
            COLLECTOR_ID));
  }

  /**
   * Creates the signature NDEF record
   *
   * @param mobileDeviceNonce Mobile device nonce to use
   * @return Signature NDEF record
   */
  private NdefRecord createSignatureRecord(byte[] mobileDeviceNonce)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException,
      InvalidKeyException, SignatureException {

    Security.addProvider(new BouncyCastleProvider());

    // Generate terminal ephemeral keys
    generateTerminalEphemeralPublicPrivateKeys();

    // Get the compressed terminal public key and nonce
    getCompressedPublicKeyAndNonce();

    // Generate a signed mobile device nonce
    byte[] signedData = generateSignature(mobileDeviceNonce);

    return new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x73, (byte) 0x69, (byte) 0x67}, // `sig` in byte-array form
        null,
        signedData);
  }

  /**
   * Generates the signature byte array for use in the signature NDEF record
   *
   * Includes the payload format byte
   *
   * @param mobileDeviceNonce Mobile device nonce
   * @return Signature byte array
   */
  private byte[] generateSignature(byte[] mobileDeviceNonce)
      throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {

    Signature signature = Signature.getInstance("SHA256withECDSA");

    // Read in the private key
    // Normally this would be from secure storage
    Reader rdr = new StringReader(LONG_TERM_PRIVATE_KEY);
    Object parsed = new PEMParser(rdr).readObject();

    // Generate the key pair
    KeyPair pair;
    pair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) parsed);
    PrivateKey signingKey = pair.getPrivate();

    // Generate the signature
    signature.initSign(signingKey);
    signature.update(terminalNonce);
    signature.update(mobileDeviceNonce);
    signature.update(COLLECTOR_ID);
    signature.update(terminalEphemeralPublicKeyCompressed);

    signedData = signature.sign();
    return Utils.concatenateByteArrays(
        new byte[]{(byte) 0x04}, // Payload format byte
        signedData);
  }

  /**
   * Gets the compressed public key and terminal nonce
   */
  private void getCompressedPublicKeyAndNonce() {
    byte[] x = terminalEphemeralPublicKey.getW().getAffineX().toByteArray();
    byte[] y = terminalEphemeralPublicKey.getW().getAffineY().toByteArray();

    BigInteger xbi = new BigInteger(1, x);
    BigInteger ybi = new BigInteger(1, y);
    X9ECParameters x9 = ECNamedCurveTable.getByName("secp256r1");
    ECCurve curve = x9.getCurve();
    ECPoint point = curve.createPoint(xbi, ybi);

    terminalEphemeralPublicKeyCompressed = point.getEncoded(true);
    terminalNonce = Utils.getRandomByteArray(32);
  }

  /**
   * Generates the terminal ephemeral key pair
   */
  private void generateTerminalEphemeralPublicPrivateKeys()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());

    KeyPair pair = keyGen.generateKeyPair();
    terminalEphemeralPublicKey = (ECPublicKey) pair.getPublic();
    terminalEphemeralPrivateKey = pair.getPrivate();
  }

  /**
   * Creates the session NDEF record
   *
   * @return Session NDEF record
   */
  private NdefRecord createSessionRecord() throws IOException {
    // Generate a random session ID
    this.sessionId = Utils.getRandomByteArray(8);

    // Return a session NDEF record
    return new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x73, (byte) 0x65, (byte) 0x73}, // `ses` in byte-array form
        null,
        Utils.concatenateByteArrays(
            sessionId,
            new byte[]{(byte) 0x01}, // Sequence number (first in sequence)
            new byte[]{(byte) 0x01} // Status byte
        ));
  }

  /**
   * Converts an instance of this class into a byte-array `negotiate secure smart tap sessions`
   * command
   *
   * @return A byte array representing the command to send
   */
  byte[] commandToByteArray() throws Exception {
    try {
      NdefMessage ndefMsg = new NdefMessage(negotiateCryptoRecord);
      int length = ndefMsg.getByteArrayLength();

      return Utils.concatenateByteArrays(
          COMMAND_PREFIX,
          new byte[]{(byte) length},
          ndefMsg.toByteArray(),
          new byte[]{(byte) 0x00});
    } catch (IOException e) {
      throw new SmartTapException(
          "Problem turning `negotiate secure smart tap sessions` command to byte array: " + e);
    }
  }
}
