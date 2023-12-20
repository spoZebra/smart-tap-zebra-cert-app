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

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import androidx.appcompat.app.AppCompatActivity;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.util.encoders.Hex;

/**
 * Activity encompassing entire Smart Tap sample
 */
public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

  private NfcAdapter nfcAdapter;
  private ArrayAdapter<?> arrayAdapter;
  private ArrayList<String> output;
  private boolean inNfcSession;
  private NegotiateCryptoResponse negotiateCryptoResponse;
  private SelectOSEResponse selectOSEResponse;
  private SelectSmartTapResponse selectSmartTapResponse;
  private NegotiateCryptoCommand negotiateCryptoCommand;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    this.nfcAdapter = NfcAdapter.getDefaultAdapter(this);
    this.output = new ArrayList<>();
    this.arrayAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, output);

    setContentView(R.layout.activity_main);

    ListView listView = findViewById(R.id.listView);
    listView.setAdapter(this.arrayAdapter);
  }

  @Override
  protected void onResume() {
    super.onResume();

    int flags = NfcAdapter.FLAG_READER_NFC_A;
    flags |= NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;

    nfcAdapter.enableReaderMode(this, this, flags, null);
  }

  @Override
  public void onPause() {
    super.onPause();

    nfcAdapter.disableReaderMode(this);
  }

  @Override
  public void onTagDiscovered(Tag tag) {
    try {
      this.output.clear();

      IsoDep isoDep = IsoDep.get(tag);
      isoDep.connect();

      if (output.size() == 0 && !inNfcSession) {
        this.performSecureGetFlow(isoDep);
      }

      isoDep.close();
    } catch (Exception e) {
      stopCommand(new StringBuilder("Error: " + e));
    }
  }

  /**
   * Runs the individual commands in the `get smart tap data` flow and parses responses
   *
   * @param isoDep ISO-DEP (ISO 14443-4) tag methods
   */
  private void performSecureGetFlow(IsoDep isoDep) {
    this.inNfcSession = true;

    // Outputs to the sample app during the flow
    StringBuilder descriptiveText = new StringBuilder("Performing secure get flow...");

    try {
      // Command: `select ose`
      performSelectOSECommand(isoDep, descriptiveText);

      // Check for the Smart Tap AID
      boolean smartTap = false;
      for (byte[] aid : selectOSEResponse.aids) {
        if (Arrays.equals(
            aid,
            new byte[]{
                (byte) 0xa0,
                (byte) 0x00,
                (byte) 0x00,
                (byte) 0x04,
                (byte) 0x76,
                (byte) 0xd0,
                (byte) 0x00,
                (byte) 0x01,
                (byte) 0x11
            })) {
          smartTap = true;
          break;
        }
      }

      if (!smartTap) {
        // Smart TAP AID not present in `select ose` response
        descriptiveText.append("\n* Smart Tap AID not detected!\n---");

        // Stop
        this.stopCommand(descriptiveText);
        return;
      }
    /**
     * --- spoZebra BEGIN ---
     * Smart tap selection must be skipped if supported
     * https://developers.google.com/wallet/smart-tap/reference/apdu-commands/select-other-system-environment?hl=en#capabilities_bitmap
     */

      //performSelectSmartTap(isoDep, descriptiveText);

      if(!selectOSEResponse.skipSmartTapSelection) {
        /**
         * --- spoZebra BEGIN ---
         * 92XX - Possible transient failure
         * The 92XX status messages mean the command failed, but that an immediate retry may succeed.
         * The terminal must retry at least one time. If the retry fails, end the session. The terminal may continue to request payment.
         * Retry 3 times here
         */
          Utils.retry(3, () -> {
            try {
              performSelectSmartTap(isoDep, descriptiveText);
            } catch (Exception e) {
              throw new RuntimeException(e);
            }
            return null;
          });
        //performSelectSmartTap(isoDep, descriptiveText);

        /**
         * --- spoZebra END ---
         */
      }

    /**
     * --- spoZebra END ---
     */
      /**
       * --- spoZebra BEGIN ---
       * 92XX - Possible transient failure
       * The 92XX status messages mean the command failed, but that an immediate retry may succeed.
       * The terminal must retry at least one time. If the retry fails, end the session. The terminal may continue to request payment.
       * Retry 3 times here
       */
      AtomicInteger deltaSeqNumber = new AtomicInteger();
      Utils.retry(3, () -> {
        try {
          performNegotiateCrypto(isoDep, descriptiveText, deltaSeqNumber.incrementAndGet());
        } catch (Exception e) {
          // Work around for testing purpose -> increment twice as the response from Smart Tap will increment it as well.
          deltaSeqNumber.incrementAndGet();
          throw new RuntimeException(e);
        }
        return null; // Since the original method returns void, we return null here
      });

      deltaSeqNumber.lazySet(0); //
      Utils.retry(3, () -> {
        try {
          performGetData(isoDep, descriptiveText, deltaSeqNumber.incrementAndGet());
        } catch (Exception e) {
          // Work around for testing purpose -> increment twice as the response from Smart Tap will increment it as well.
          deltaSeqNumber.incrementAndGet();
          throw new RuntimeException(e);
        }
        return null; // Since the original method returns void, we return null here
      });
      // Command: `negotiate smart tap secure sessions`
      //performNegotiateCrypto(isoDep, descriptiveText);
      // Command: `get smart tap data`
      //performGetData(isoDep, descriptiveText);
      /**
       * --- spoZebra END ---
       */

      // Stop
      this.stopCommand(descriptiveText);
    } catch (Exception e) {
      // Something went wrong...
      descriptiveText
          .append("\n\nError: ")
          .append(e);

      // Stop
      this.stopCommand(descriptiveText);
    }
  }

  /**
   * Performs `select ose` command and parses its response https://developers.google.com/wallet/smart-tap/reference/apdu-commands/select-other-system-environment
   *
   * @param isoDep ISO-DEP (ISO 14443-4) tag methods
   * @param descriptiveText Smart Tap response data to be surfaced on the device
   */
  private void performSelectOSECommand(IsoDep isoDep, StringBuilder descriptiveText)
      throws Exception {

    byte[] response = isoDep.transceive(
        new byte[]{
            (byte) 0x00,
            (byte) 0xA4,
            (byte) 0x04,
            (byte) 0x00,
            (byte) 0x0A,
            (byte) 0x4F,
            (byte) 0x53,
            (byte) 0x45,
            (byte) 0x2E,
            (byte) 0x56,
            (byte) 0x41,
            (byte) 0x53,
            (byte) 0x2E,
            (byte) 0x30,
            (byte) 0x31,
            (byte) 0x00
        });

    this.selectOSEResponse = new SelectOSEResponse(response);

    descriptiveText
        .append("\n----\nSent `select ose` command...\n")
        .append("\nResponse parsed:\n");

    // Response status
    descriptiveText
        .append("\n* Status:\n  ")
        .append(selectOSEResponse.status)
        .append(" (ISO 7816-4)\n");

    // Wallet application label
    descriptiveText
        .append("\n* Wallet application label:\n  ")
        .append(selectOSEResponse.walletApplicationLabel)
        .append("\n");

    // Mobile device nonce
    descriptiveText
        .append("\n* Mobile device nonce:\n  ")
        .append(Hex.toHexString(selectOSEResponse.mobileDeviceNonce))
        .append("\n");

    // Mobile device ephemeral key
    descriptiveText
        .append("\n* Mobile device ephemeral key:\n  ")
        .append(Hex.toHexString(selectOSEResponse.mobileDeviceEphemeralKey))
        .append("\n");

    // Application entries
    for (String app : selectOSEResponse.applications) {
      descriptiveText
          .append("\n* Application entry:\n  ")
          .append(app)
          .append("\n");
    }

    // End
    descriptiveText.append("\n----\n");


    /**
     * --- spoZebra BEGIN ---
     * The minimum and maximum versions represent the range of versions allowed in future commands.
     * All currently-certified Smart Tap commands use version 0001, which refers to Smart Tap version 2.1.
     * The terminal should proceed to the next command only if version 0001 is included in the interval defined by the minimum and maximum versions.
     */
    if(selectOSEResponse.minVersion > (long)0001 || selectOSEResponse.maxVersion < (long)0001){
      throw new SmartTapException("Unsupported Smart Tap 2.X mimimum version");
    }
    /**
     * --- spoZebra END ---
     */

  }

  /**
   * Performs `select smart tap 2` and parses its response https://developers.google.com/wallet/smart-tap/reference/apdu-commands/select-smart-tap-2
   *
   * @param isoDep ISO-DEP (ISO 14443-4) tag methods
   * @param descriptiveText Smart Tap response data to be surfaced on the device
   */
  private void performSelectSmartTap(IsoDep isoDep, StringBuilder descriptiveText)
      throws Exception {

    byte[] response = isoDep.transceive(
        new byte[]{
            (byte) 0x00,
            (byte) 0xA4,
            (byte) 0x04,
            (byte) 0x00,
            (byte) 0x09,
            (byte) 0xA0,
            (byte) 0x00,
            (byte) 0x00,
            (byte) 0x04,
            (byte) 0x76,
            (byte) 0xD0,
            (byte) 0x00,
            (byte) 0x01,
            (byte) 0x11,
            (byte) 0x00
        });

    this.selectSmartTapResponse = new SelectSmartTapResponse(response);

    descriptiveText
        .append("\n----\nSent `select smart tap 2` command...\n")
        .append("\nResponse parsed:\n");

    // Status
    descriptiveText
        .append("\n* Status:\n  ")
        .append(selectSmartTapResponse.status)
        .append(" (ISO 7816-4)\n");

    // Minimum version
    descriptiveText
        .append("\n* Minimum Version:\n  ")
        .append(selectSmartTapResponse.minimumVersion)
        .append("\n");

    // Maximum version
    descriptiveText
        .append("\n* Maximum Version:\n  ")
        .append(selectSmartTapResponse.maximumVersion)
        .append("\n");
    /**
     * --- spoZebra BEGIN ---
     * As Smart tap selection could be skipped,
     * let's use the mobile device nonce coming from FCI template
     */
    /*
    if (selectSmartTapResponse.mobileDeviceNonce != null) {
      // Mobile device nonce
      descriptiveText
          .append("\n* Mobile Device Nonce:\n  ")
          .append(Hex.toHexString(selectSmartTapResponse.mobileDeviceNonce))
          .append("\n");
    }*/
    /**
     * --- spoZebra END ---
     */
    // End
    descriptiveText.append("\n----\n");
  }

  /**
   * Performs `negotiate smart tap secure sessions` and parses its response
   * https://developers.google.com/wallet/smart-tap/reference/apdu-commands/negotiate-secure-sessions
   *
   * @param isoDep ISO-DEP (ISO 14443-4) tag methods
   * @param descriptiveText Smart Tap response data to be surfaced on the device
   */

  /**
   * --- spoZebra BEGIN ---
   * Update sequence command as a retry could be fired
   */
  //private void performNegotiateCrypto(IsoDep isoDep, StringBuilder descriptiveText)
  private void performNegotiateCrypto(IsoDep isoDep, StringBuilder descriptiveText, int sequenceNumber)
          throws Exception {
  /**
   * --- spoZebra END ---
   */
  /**
   * --- spoZebra BEGIN ---
   * As Smart tap selection could be skipped,
   * let's use the mobile device nonce coming from FCI template if sm select command was not issued
   */

  // this.negotiateCryptoCommand = new NegotiateCryptoCommand(this.selectSmartTapResponse.mobileDeviceNonce);

    byte[] mobileDeviceNonce = this.selectOSEResponse.mobileDeviceNonce;

    if(this.selectSmartTapResponse != null)
      mobileDeviceNonce = this.selectSmartTapResponse.mobileDeviceNonce;

    /**
     * --- spoZebra BEGIN ---
     * Update sequence command as a retry could be fired
     */
    this.negotiateCryptoCommand = new NegotiateCryptoCommand(mobileDeviceNonce, sequenceNumber);
    /**
     * --- spoZebra END ---
     */
  /**
   * --- spoZebra END ---
   */
    byte[] response = isoDep.transceive(negotiateCryptoCommand.commandToByteArray());
    this.negotiateCryptoResponse = new NegotiateCryptoResponse(response);

    descriptiveText
        .append("\n----\nSent `negotiate smart tap secure sessions` command...")
        .append("\nResponse parsed:\n");

    // Status last 4
    descriptiveText
        .append("\n* Status:\n  ")
        .append(this.negotiateCryptoResponse.status)
        .append(" (ISO 7816-4)\n");

    // Mobile device ephemeral public key
    descriptiveText
        .append("\n* Mobile device ephemeral public key (compressed):\n  ")
        .append(Hex.toHexString(this.negotiateCryptoResponse.mobileDeviceEphemeralPublicKey))
        .append('\n');

    // End
    descriptiveText.append("\n----\n");
  }

  /**
   * Performs `get smart tap data` and parses its response https://developers.google.com/wallet/smart-tap/reference/apdu-commands/get-data
   *
   * @param isoDep ISO-DEP (ISO 14443-4) tag methods
   * @param descriptiveText Smart Tap response data to be surfaced on the device
   */
  /**
   * --- spoZebra BEGIN ---
   * Update sequence command as a retry could be fired
   */
  /*private void performGetData(IsoDep isoDep, StringBuilder descriptiveText) throws Exception {
  GetDataCommand getDataCommand = new GetDataCommand(
          this.negotiateCryptoCommand.sessionId,
          this.negotiateCryptoCommand.collectorIdRecord,
          this.negotiateCryptoResponse.sequenceNumber + 1);*/
  private void performGetData(IsoDep isoDep, StringBuilder descriptiveText, int deltaSeqNumber) throws Exception {

    GetDataCommand getDataCommand = new GetDataCommand(
        this.negotiateCryptoCommand.sessionId,
        this.negotiateCryptoCommand.collectorIdRecord,
        this.negotiateCryptoResponse.sequenceNumber + deltaSeqNumber);
    /**
     * --- spoZebra END ---
     */
    byte[] getDataResponse = isoDep.transceive(getDataCommand.commandToByteArray());

    /**
     * --- spoZebra BEGIN ---
     * The response data may be chunked over multiple APDUs.
     * First, the terminal should retrieve the payload in the reb record.
     * Next, it should get the payload from any Response: get additional smart tap data
     *
     * 9100 indicates that there is additional data, so the terminal needs to make another get additional smart tap data request.
     */

    // Check first get data status
    String statusData = Utils.getStatus(getDataResponse);
    Utils.checkStatusResponse(statusData);

    byte[] getAdditionalDataResponse = null;
    if(statusData.equals("9100")) {
      // Send get additional data request
      GetAdditionalDataCommand getAdditionalDataCommand = new GetAdditionalDataCommand();
      getAdditionalDataResponse = isoDep.transceive(getAdditionalDataCommand.commandToByteArray());
      // Get status
      String statusAdditionalData = Utils.getStatus(getAdditionalDataResponse);
      // Check get additional data status
      Utils.checkStatusResponse(statusAdditionalData);
    }
    /**
     * --- spoZebra END ---
     */
    /**
     * --- spoZebra BEGIN ---
     * As Smart tap selection could be skipped,
     * let's use the mobile device nonce coming from FCI template
     */
    GetDataResponse getDecryptedDataResponse = new GetDataResponse(
        getDataResponse,
        getAdditionalDataResponse,
        negotiateCryptoResponse.mobileDeviceEphemeralPublicKey,
        negotiateCryptoCommand.terminalEphemeralPrivateKey,
        negotiateCryptoCommand.terminalNonce,
        NegotiateCryptoCommand.COLLECTOR_ID,
        negotiateCryptoCommand.terminalEphemeralPublicKeyCompressed,
        negotiateCryptoCommand.signedData,
        // selectSmartTapResponse.mobileDeviceNonce
        selectOSEResponse.mobileDeviceNonce);
    /**
     * --- spoZebra END ---
     */
    descriptiveText.append("\n----\nSent `get smart tap data` command...");

    // Decrypted smartTapRedemptionValue from the pass
    descriptiveText.append("\nResponse parsed and decrypted, contents:\n  ");
    descriptiveText.append(getDecryptedDataResponse.decryptedSmartTapRedemptionValue);

    // End
    descriptiveText.append("\n----\n");
  }

  /**
   * Stops the Smart Tap flow
   *
   * @param descriptiveText Smart Tap response data to be surfaced on the device
   */
  private void stopCommand(final StringBuilder descriptiveText) {

    // Add output
    this.output.add(descriptiveText.toString());

    // Clear responses
    this.negotiateCryptoResponse = null;
    this.selectOSEResponse = null;
    this.selectSmartTapResponse = null;
    this.negotiateCryptoCommand = null;

    // Update the UI
    runOnUiThread(() -> {
      arrayAdapter.notifyDataSetChanged();
      inNfcSession = false;
    });
  }
}
