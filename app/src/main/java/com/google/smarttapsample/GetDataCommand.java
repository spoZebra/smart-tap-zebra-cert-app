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

/**
 * Class encapsulates the creation of the `get smart tap data` command
 * https://developers.google.com/wallet/smart-tap/reference/apdu-commands/get-data#command_get_smart_tap_data
 */
class GetDataCommand {

  private static final byte[] COMMAND_PREFIX = new byte[]{
      (byte) 0x90,
      (byte) 0x50,
      (byte) 0x00,
      (byte) 0x00
  };

  /**
   * --- spoZebra BEGIN ---
   * Requested service type -> ALL
   */
  // private static final byte SERVICE_TYPE = 0x03;
  private static final byte SERVICE_TYPE = 0x00;
  /**
   * --- spoZebra END ---
   */

  private NdefRecord serviceRequestRecord;

  /**
   * Constructor for the class
   *
   * @param sessionId Session ID from context of Smart Tap
   * @param collectorIdRecord Collector ID NDEF record
   * @param sequenceNumber The sequence number to use
   */
  GetDataCommand(byte[] sessionId, NdefRecord collectorIdRecord, int sequenceNumber)
      throws Exception {

    try {
      NdefRecord sessionRecord = createSessionRecord(sessionId, sequenceNumber);
      NdefRecord merchantRecord = createMerchantRecord(collectorIdRecord);
      NdefRecord serviceListRecord = createServiceListRecord();
      createServiceRequestRecord(sessionRecord, merchantRecord, serviceListRecord);

    } catch (Exception e) {
      throw new SmartTapException("Problem creating `get smart tap data` command: " + e);
    }
  }

  /**
   * Creates a service request NDEF record from session, merchant, and service list NDEF records
   *
   * @param sessionRecord Session NDEF record
   * @param merchantRecord Merchant NDEF record
   * @param serviceListRecord Service list NDEF record
   */
  private void createServiceRequestRecord(
      NdefRecord sessionRecord, NdefRecord merchantRecord, NdefRecord serviceListRecord)
      throws IOException {

    // Service request NDEF record encapsulates all
    NdefMessage serviceRequestNdefMessagePayload = new NdefMessage(sessionRecord, merchantRecord,
        serviceListRecord);

    serviceRequestRecord = new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x73, (byte) 0x72, (byte) 0x71}, // `srq` in byte-array form
        null,
        Utils.concatenateByteArrays(
            new byte[]{(byte) 0x00, (byte) 0x01}, // Service request ndef
            serviceRequestNdefMessagePayload.toByteArray()));
  }

  /**
   * Creates a loyalty service list NDEF record https://developers.google.com/wallet/smart-tap/reference/apdu-commands/get-data#service_type_request_ndef_record
   *
   * @return Service list NDEF record
   */
  private static NdefRecord createServiceListRecord() {
    // Create a service type NDEF record that will go into the service list NDEF
    // record
    NdefRecord serviceTypeRecord = new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x73, (byte) 0x74, (byte) 0x72}, // `str` in byte-array form
        null,
        new byte[]{SERVICE_TYPE});
    NdefMessage serviceListRecordPayload = new NdefMessage(serviceTypeRecord);

    // Return the service list NDEF record
    return new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x73, (byte) 0x6C, (byte) 0x72}, // `slr` in byte array form
        null,
        serviceListRecordPayload.toByteArray());
  }

  /**
   * Creates merchant NDEF record
   *
   * @param collectorIdRecord Collector ID record portion of the merchant ID record
   * @return Merchant NDEF record
   */
  private static NdefRecord createMerchantRecord(NdefRecord collectorIdRecord) {
    return new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x6D, (byte) 0x65, (byte) 0x72}, // `mer` in byte-array form
        null,
        (new NdefMessage(collectorIdRecord).toByteArray()));
  }

  /**
   * Creates a session NDEF record using session ID
   *
   * @param sessionId Smart Tap session ID
   * @param sequenceNumber The sequence number to use
   * @return Session NDEF record
   */
  private static NdefRecord createSessionRecord(byte[] sessionId, int sequenceNumber)
      throws IOException {
    return new NdefRecord(
        NdefRecord.TNF_EXTERNAL_TYPE,
        new byte[]{(byte) 0x73, (byte) 0x65, (byte) 0x73}, // `ses` in byte-array form
        null,
        Utils.concatenateByteArrays(
            sessionId,
            new byte[]{(byte) sequenceNumber},
            new byte[]{(byte) 0x01} // Status byte
        ));
  }

  /**
   * Converts an instance of this class into a byte-array `get smart tap data` command
   *
   * @return A byte array representing the command to send
   */
  byte[] commandToByteArray() throws Exception {
    try {
      NdefMessage ndefMsg = new NdefMessage(serviceRequestRecord);
      int length = ndefMsg.getByteArrayLength();

      return Utils.concatenateByteArrays(
          COMMAND_PREFIX,
          new byte[]{(byte) length},
          ndefMsg.toByteArray(),
          new byte[]{(byte) 0x00});
    } catch (Exception e) {
      throw new SmartTapException(
          "Problem turning `get smart tap data` command to byte array: " + e);
    }
  }
}
