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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Objects;
import java.util.function.Supplier;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;

/**
 * Class for general utility methods for byte-array operations
 */
class Utils {

  /**
   * Parses data in TLV format as per BER-TLV (ISO/IEC 7816-4)
   *
   * @param data The data to parse
   * @return The TLV data structured in key/value pairs where key is a hex string
   */
  static HashMap<String, ArrayList<byte[]>> parseTLV(byte[] data) {
    HashMap<String, ArrayList<byte[]>> parsedData = new HashMap<>();

    // Iterate through the byte array
    int i = 0;
    while (i < data.length) {
      // Get the type
      String type = Hex.toHexString(new byte[]{data[i]}).toUpperCase();

      if (type.startsWith("DF") || type.startsWith("BF")) {
        // Types starting with "DF" and "BF" have an additional byte
        i += 1;
        type += Hex.toHexString(new byte[]{data[i]}).toUpperCase();
      }

      i += 1;
      String length = Hex.toHexString(new byte[]{data[i]});
      int value_length = 0;
      switch (length) {
        case "81":
          // Two bytes for length expression
          i += 1;
          value_length = (int) unsignedIntToLong(new byte[]{0x00, 0x00, 0x00, data[i]});
          i += 1;
          break;
        case "82":
          // Three bytes for length expression
          i += 1;
          value_length = (int) unsignedIntToLong(new byte[]{0x00, 0x00, data[i], data[i + 1]});
          i += 2;
          break;
        case "83":
          // Four bytes for length expression
          i += 1;
          value_length = (int) unsignedIntToLong(
              new byte[]{0x00, data[i], data[i + 1], data[i + 2]});
          i += 3;
          break;
        case "84":
          // Five bytes for length expression
          i += 1;
          value_length = (int) unsignedIntToLong(
              new byte[]{data[i], data[i + 1], data[i + 2], data[i + 3]});
          i += 4;
          break;
        default:
          value_length = (int) unsignedIntToLong(new byte[]{0x00, 0x00, 0x00, data[i]});
          i += 1;
          break;
      }

      // Extract the value from i to value_length
      byte[] value = Arrays.copyOfRange(data, i, i + value_length);

      // Add key/value pair to output hash map
      if (parsedData.containsKey(type)) {
        Objects.requireNonNull(parsedData.get(type)).add(value);
      } else {
        parsedData.put(type, new ArrayList<>(Collections.singletonList(value)));
      }
      i += value_length;
    }
    return parsedData;
  }

  /**
   * Converts a byte array representing an unsigned integer (4bytes) to its long equivalent
   *
   * @param b byte[]
   * @return long
   */
  static long unsignedIntToLong(byte[] b) {
    long l = 0;

    l |= b[0] & 0xFF;
    l <<= 8;
    l |= b[1] & 0xFF;
    l <<= 8;
    l |= b[2] & 0xFF;
    l <<= 8;
    l |= b[3] & 0xFF;

    return l;
  }

  /**
   * Generates a random byte array of specified length
   *
   * @param length int
   * @return long
   */
  static byte[] getRandomByteArray(int length) {
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[length];

    random.nextBytes(bytes);

    return bytes;
  }

  /**
   * Generates an EC public key from a byte array
   *
   * @param pubKey Public key in byte-array form
   * @return Public key object
   */
  static PublicKey getPublicKeyFromBytes(byte[] pubKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {

    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
    ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(),
        spec.getN());
    ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
    ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);

    return kf.generatePublic(pubKeySpec);
  }

  /**
   * Concatenates byte arrays
   *
   * @param bytes Byte arrays to concatenate
   * @return Concatenated byte array
   */
  static byte[] concatenateByteArrays(byte[]... bytes) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    for (byte[] b : bytes) {
      output.write(b);
    }

    return output.toByteArray();
  }

  /**
   * Gets the status from a Smart Tap response
   *
   * @param response Smart Tap response to parse
   * @return Status code
   */
  static String getStatus(byte[] response) {
    return Hex.toHexString(Arrays.copyOfRange(response, response.length - 2, response.length));
  }

  /**
   * Gets the payload from a Smart Tap response
   *
   * @param response Smart Tap response to parse
   * @return Payload in byte-array form
   */
  static byte[] extractPayload(byte[] response) {
    return Arrays.copyOfRange(response, 0, response.length - 2);
  }
  /**
   * --- spoZebra BEGIN ---
   * Handle SmartTap retries using this function
   */
  public static <T> T retry(int maxRetries, Supplier<T> action) throws Exception {
    for (int attempt = 0; ; attempt++) {
      try {
        return action.get();
      } catch (Exception ex) {
        if(!(ex.getCause() instanceof SmartTapRetryRequested) || attempt >= maxRetries){
          throw ex; // If the error does not require a retry or max attempts were reached already, propagate the exception
        }
      }
    }
  }
  /**
   * --- spoZebra END ---
   */

  /**
   * --- spoZebra BEGIN ---
   * 92XX - Possible transient failure
   * The 92XX status messages mean the command failed, but that an immediate retry may succeed.
   * The terminal must retry at least one time. If the retry fails, end the session. The terminal may continue to request payment.
   */
  public static void checkStatusResponse(String status) throws Exception {
    if(status.startsWith("92")){
      throw new SmartTapRetryRequested();
    }
    else if (!status.startsWith("90") && !status.startsWith("91")) {
      // Invalid status code
      // https://developers.google.com/wallet/smart-tap/reference/apdu-commands/status-words
      throw new SmartTapException("Invalid status: Additional Data:" + status);
    }
  }
  /**
   * --- spoZebra END ---
   */
}
