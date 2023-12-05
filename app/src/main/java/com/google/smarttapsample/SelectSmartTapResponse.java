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
import java.util.Arrays;

/**
 * Class encapsulates the response from the `select ose` command https://developers.google.com/wallet/smart-tap/reference/apdu-commands/select-smart-tap-2
 */
class SelectSmartTapResponse {

  String minimumVersion;
  String maximumVersion;
  String status;
  /**
   * --- spoZebra BEGIN ---
   * As Smart tap selection could be skipped,
   * let's use the mobile device nonce coming from FCI template
   */
  //byte[] mobileDeviceNonce;
  /**
   * --- spoZebra END ---
   */

  /**
   * Constructor for the class
   *
   * @param response Response from the `select smart tap 2` command
   */
  SelectSmartTapResponse(byte[] response) throws Exception {
    // Extract status
    this.status = Utils.getStatus(response);

    if (!this.status.equals("9000")) {
      throw new SmartTapException("Invalid Status: " + this.status);
    }

    try {
      // Extract minimum and maximum versions
      byte[] payload = Utils.extractPayload(response);
      byte[] fourBytePayload = new byte[]{0x00, 0x00, payload[0], payload[1]};

      minimumVersion = Integer.toString((int) Utils.unsignedIntToLong(fourBytePayload));

      byte[] byteNum = Arrays.copyOfRange(response, 2, 4);
      byte[] fourByteNum = new byte[]{0x00, 0x00, byteNum[0], byteNum[1]};

      maximumVersion = Integer.toString((int) Utils.unsignedIntToLong(fourByteNum));
      /**
       * --- spoZebra BEGIN ---
       * As Smart tap selection could be skipped,
       * let's use the mobile device nonce coming from FCI template
       */
      // Extract mobile device nonce
      /*NdefMessage mdnNdefMessage = new NdefMessage(
          Arrays.copyOfRange(response, 4, response.length - 2));
      this.mobileDeviceNonce = Arrays.copyOfRange(
          mdnNdefMessage.getRecords()[0].getPayload(),
          1,
          mdnNdefMessage.getRecords()[0].getPayload().length);*/
      /**
       * --- spoZebra END ---
       */
    } catch (Exception e) {
      throw new SmartTapException("Problem parsing `select smart tap 2` response: " + e);
    }
  }
}
