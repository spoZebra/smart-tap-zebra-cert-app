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
import java.util.Arrays;

/**
 * Class encapsulates the response from the `negotiate secure smart tap sessions` command
 * https://developers.google.com/wallet/smart-tap/reference/apdu-commands/negotiate-secure-sessions
 */
class NegotiateCryptoResponse {

  int sequenceNumber;
  String status;
  byte[] mobileDeviceEphemeralPublicKey;

  /**
   * Constructor for the class
   *
   * @param response Response from the `negotiate secure smart tap sessions` command
   */
  NegotiateCryptoResponse(byte[] response) throws Exception {
    try {
      // Extract status
      this.status = Utils.getStatus(response);
      checkStatus();

      // Extract the negotiate request NDEF record
      NdefRecord negotiateRequestRecord = getNegotiateRequestRecord(Utils.extractPayload(response));

      // Iterate over inner request NDEF records
      for (NdefRecord rec : (new NdefMessage(negotiateRequestRecord.getPayload()).getRecords())) {
        // Looking for `ses`
        if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x73, (byte) 0x65, (byte) 0x73})) {
          // Get the sequence number
          sequenceNumber = rec.getPayload()[8];
        }
        // Looking for `dpk`
        if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x64, (byte) 0x70, (byte) 0x6B})) {
          // Get the mobile device ephemeral public key
          mobileDeviceEphemeralPublicKey = rec.getPayload();
        }
      }
    } catch (Exception e) {
      /**
     * --- spoZebra BEGIN ---
     * 92XX - Possible transient failure
     * The 92XX status messages mean the command failed, but that an immediate retry may succeed.
     * The terminal must retry at least one time. If the retry fails, end the session. The terminal may continue to request payment.
     */
      throw e;
      //throw new SmartTapException("Problem parsing `negotiate secure smart tap sessions` response: " + e);
      /**
       * --- spoZebra END ---
       */
    }
  }

  /**
   * Checks the overall response status https://developers.google.com/wallet/smart-tap/reference/apdu-commands/status-words
   */
  private void checkStatus() throws Exception {
    // Check if status is valid
    if (!this.status.equals("9000")) {
      /**
       * --- spoZebra BEGIN ---
       * 92XX - Possible transient failure
       * The 92XX status messages mean the command failed, but that an immediate retry may succeed.
       * The terminal must retry at least one time. If the retry fails, end the session. The terminal may continue to request payment.
       */
      if(this.status.startsWith("92")){
        throw new SmartTapRetryRequested();
      }
      /**
       * --- spoZebra END ---
       */
      else if (this.status.equals("9500")) {
        throw new SmartTapException("Unable to authenticate");
      } else {
        throw new SmartTapException("Invalid Status: " + this.status);
      }
    }
  }

  /**
   * Gets the negotiate request NDEF record from the response
   *
   * @param payload Byte-array of response
   * @return Negotiate request NDEF record
   */
  private static NdefRecord getNegotiateRequestRecord(byte[] payload) throws Exception {
    // Get records from the payload
    NdefRecord[] records = (new NdefMessage(payload)).getRecords();

    for (NdefRecord rec : records) {
      // Looking for `ngr`
      if (Arrays.equals(rec.getType(), new byte[]{(byte) 0x6E, (byte) 0x72, (byte) 0x73})) {
        return rec;
      }
    }

    throw new SmartTapException("No record bundle found!");
  }
}
