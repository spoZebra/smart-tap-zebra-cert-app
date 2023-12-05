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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;
import org.bouncycastle.util.encoders.Hex;

/**
 * Class encapsulates the response from the `select ose` command https://developers.google.com/wallet/smart-tap/reference/apdu-commands/select-other-system-environment
 */
class SelectOSEResponse {

  /**
   * --- spoZebra BEGIN ---
   * Smart tap selection must be skipped when supported
   */
  boolean skipSmartTapSelection;
  /**
   * --- spoZebra END ---
   */
  ArrayList<byte[]> aids = new ArrayList<>();
  String status;
  String walletApplicationLabel;
  String transactionMode;
  byte[] mobileDeviceNonce;
  byte[] mobileDeviceEphemeralKey;
  ArrayList<String> applications = new ArrayList<>();

  /**
   * Constructor for the class
   *
   * @param response Response from the `select ose` command
   */
  SelectOSEResponse(byte[] response) throws Exception {
    // Extract status
    this.status = Utils.getStatus(response);

    if (!status.startsWith("9")) {
      // Invalid status code
      // https://developers.google.com/wallet/smart-tap/reference/apdu-commands/status-words
      throw new SmartTapException("Invalid status: " + status);
    }

    // Extract the data from the response
    try {
      HashMap<String, ArrayList<byte[]>> baseTLV = Utils.parseTLV(Utils.extractPayload(response));
      HashMap<String, ArrayList<byte[]>> fciPPSEdata = checkBaseTemplateAndExtractProperties(
          baseTLV);

      if (fciPPSEdata.isEmpty() || fciPPSEdata.getOrDefault("61", null) == null) {
        return;
      }

      for (byte[] entry : Objects.requireNonNull(fciPPSEdata.get("61"))) {
        if (getDirectoryEntry(entry)) {
          return;
        }
      }
    } catch (Exception e) {
      throw new SmartTapException("Problem parsing `select ose` response: " + e);
    }
  }

  /**
   * Extracts info from the FCI template in the `select ose` response
   *
   * @param baseTLV Base TLV to extract information from
   * @return TLV for the result
   */
  private HashMap<String, ArrayList<byte[]>> checkBaseTemplateAndExtractProperties(
      HashMap<String, ArrayList<byte[]>> baseTLV) throws Exception {

    if (!baseTLV.containsKey("6F")) {
      throw new SmartTapException("Problem parsing `select ose` response: No FCI template!");
    }

    // Parse the `6F` TLV
    HashMap<String, ArrayList<byte[]>> fciTemplateContentTLV = Utils.parseTLV(
        Objects.requireNonNull(baseTLV.get("6F")).get(0));

    if (!fciTemplateContentTLV.containsKey("50")) {
      throw new SmartTapException("Problem parsing `select ose` response: No application label!");
    }

    // Parse the Wallet application label
    this.walletApplicationLabel = new String(
        Objects.requireNonNull(fciTemplateContentTLV.get("50")).get(0));

    if (!fciTemplateContentTLV.containsKey("C0")) {
      throw new SmartTapException("Problem parsing `select ose` response: No application version!");
    }

    if (!fciTemplateContentTLV.containsKey("C1")) {
      throw new SmartTapException("Problem parsing `select ose` response: No transaction details!");
    }

    // Parse the transaction details
    byte[] transactionDetailBitmap = Objects.requireNonNull(fciTemplateContentTLV.get("C1")).get(0);

    // Get the transaction mode
    this.transactionMode = getTransactionMode(transactionDetailBitmap[0]);

    if (fciTemplateContentTLV.containsKey("C2")) {
      // Get the mobile device nonce
      this.mobileDeviceNonce = Objects.requireNonNull(fciTemplateContentTLV.get("C2")).get(0);
    }

    if (fciTemplateContentTLV.containsKey("C3")) {
      // Get the mobile device ephemeral key
      this.mobileDeviceEphemeralKey = Objects.requireNonNull(fciTemplateContentTLV.get("C3"))
          .get(0);
    }

    if (!fciTemplateContentTLV.containsKey("A5")) {
      throw new SmartTapException(
          "Problem parsing `select ose` response: No FCI proprietary template!");
    }

    // Parse the FCI proprietary template
    HashMap<String, ArrayList<byte[]>> fciProprietaryTemplateContentTLV = Utils
        .parseTLV(Objects.requireNonNull(fciTemplateContentTLV.get("A5")).get(0));

    if (!fciProprietaryTemplateContentTLV.containsKey("BF0C")) {
      throw new SmartTapException("Problem parsing `select ose` response: No FCI PPSE data!");
    }

    // Parse the FCI PPSE data
    HashMap<String, ArrayList<byte[]>> fciPPSEdata = Utils
        .parseTLV(Objects.requireNonNull(fciProprietaryTemplateContentTLV.get("BF0C")).get(0));

    if (!fciPPSEdata.containsKey("61")) {
      throw new SmartTapException("Problem parsing `select ose` response: No directory entries!");
    }

    return fciPPSEdata;
  }

  /**
   * Gets the application details from a directory entry
   *
   * @param entry Byte-array representation of a directory entry
   * @return Directory entry was successfully extracted
   */
  private boolean getDirectoryEntry(byte[] entry) throws Exception {
    // Parse the entry
    HashMap<String, ArrayList<byte[]>> directoryEntryContentTLV = Utils.parseTLV(entry);

    if (!directoryEntryContentTLV.containsKey("4F")) {
      throw new SmartTapException("Problem parsing `select ose` response: No ADF name!");
    }

    // Get the ADF name
    byte[] aid = Objects.requireNonNull(directoryEntryContentTLV.get("4F")).get(0);
    aids.add(aid);
    String adfName = Hex.toHexString(aid);

    // Entry data to output
    StringBuilder directoryEntry = new StringBuilder("\nApplication Name: " + adfName);

    // Get label
    if (directoryEntryContentTLV.containsKey("50")) {
      String label = new String(Objects.requireNonNull(directoryEntryContentTLV.get("50")).get(0));

      directoryEntry
          .append(", Label: ")
          .append(label);
    }

    // Get priority
    if (directoryEntryContentTLV.containsKey("87")) {
      byte[] bytesNum = Objects.requireNonNull(directoryEntryContentTLV.get("87")).get(0);
      byte[] fourByteNum = new byte[]{0x00, 0x00, 0x00, bytesNum[0]};
      int priority = (int) Utils.unsignedIntToLong(fourByteNum);

      directoryEntry
          .append(", Priority: ")
          .append(priority);
    }

    // Get discretionary template
    if (directoryEntryContentTLV.containsKey("73")) {
      getDiscretionaryTemplateInfo(directoryEntryContentTLV, aid, directoryEntry);
    }

    applications.add(directoryEntry.toString());

    return false;
  }

  /**
   * Parses the discretionary template data
   *
   * @param directoryEntryContentTLV Data as a TLV
   * @param aid Byte array AID
   * @param directoryEntry Directory entry output
   */
  private void getDiscretionaryTemplateInfo(
      HashMap<String, ArrayList<byte[]>> directoryEntryContentTLV,
      byte[] aid,
      StringBuilder directoryEntry) {

    // Parse the TLV data
    HashMap<String, ArrayList<byte[]>> discretionaryTemplateContentTLV = Utils
        .parseTLV(Objects.requireNonNull(directoryEntryContentTLV.get("73")).get(0));

    // Get the minimum version
    if (discretionaryTemplateContentTLV.containsKey("DF6D")) {
      byte[] bytesNum = Objects.requireNonNull(discretionaryTemplateContentTLV.get("DF6D")).get(0);
      byte[] fourByteNum = new byte[]{0x00, 0x00, bytesNum[0], bytesNum[1]};
      int applicationMinimumVersion = (int) Utils.unsignedIntToLong(fourByteNum);

      directoryEntry
          .append(", Minimum Version: ")
          .append(applicationMinimumVersion);
    }

    // Get the maximum version
    if (discretionaryTemplateContentTLV.containsKey("DF4D")) {
      byte[] num = Objects.requireNonNull(discretionaryTemplateContentTLV.get("DF4D")).get(0);
      byte[] byte_num = new byte[]{0x00, 0x00, num[0], num[1]};
      int applicationMaximumVersion = (int) Utils.unsignedIntToLong(byte_num);

      directoryEntry
          .append(", Maximum Version: ")
          .append(applicationMaximumVersion);
    }

    // Get the mobile device nonce
    if (discretionaryTemplateContentTLV.containsKey("DF6E")) {
      this.mobileDeviceNonce = Objects.requireNonNull(discretionaryTemplateContentTLV.get("DF6E"))
          .get(0);
    }

    // Get the mobile device ephemeral key
    if (discretionaryTemplateContentTLV.containsKey("DF6B")) {
      this.mobileDeviceEphemeralKey = Objects.requireNonNull(
          discretionaryTemplateContentTLV.get("DF6B")).get(0);
    }

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

      // Get the Smart Tap capabilities
      getSmartTapCapabilities(directoryEntry, discretionaryTemplateContentTLV);
    }
  }

  /**
   * Gets the Smart Tap capabilities.
   *
   * @param directoryEntry Directory entry output
   * @param discretionaryTemplateContentTLV Data as a TLV
   */
  private void getSmartTapCapabilities(
          StringBuilder directoryEntry,
          HashMap<String, ArrayList<byte[]>> discretionaryTemplateContentTLV) {

    /**
     * --- spoZebra BEGIN ---
     * When the allow skipping second select bit is set to 1, the terminal should skip the select smart tap 2 command.
     * When the allow skipping second select bit is set to 0, the terminal must not skip this command.
     */
    skipSmartTapSelection = false;
    /**
     * --- spoZebra END ---
     */
    // Parse the capabilities bitmap
    if (discretionaryTemplateContentTLV.containsKey("DF62")) {
      int capabilitiesBitMap = Objects.requireNonNull(discretionaryTemplateContentTLV.get("DF62"))
          .get(0)[0];

      switch (capabilitiesBitMap) {
        case 0:
          directoryEntry.append(", Capabilities: No extra capabilities from bitmap");
          break;
        case 1:
          directoryEntry.append(", Capabilities: Allow skipping second select");
          break;
        case 2:
          directoryEntry.append(", Capabilities: VAS support");
          break;
        case 3:

          /**
           * --- spoZebra BEGIN ---
           * When the allow skipping second select bit is set to 1, the terminal should skip the select smart tap 2 command.
           * When the allow skipping second select bit is set to 0, the terminal must not skip this command.
           */
          skipSmartTapSelection = true;
          /**
           * --- spoZebra END ---
           */
          directoryEntry.append(", Capabilities: VAS support and allow skipping second select");
          break;
      }
    }
  }

  /**
   * Get the transaction mode
   *
   * @param b bitmap
   */
  private static String getTransactionMode(byte b) throws SmartTapException {
    switch ((int) b & 0xFF) {
      case 204:
        return "Payment and Pass enabled and requested";
      case 200:
        return "Payment enabled and requested, Pass enabled";
      case 192:
        return "Payment enabled and requested";
      case 140:
        return "Payment enabled, Pass enabled and requested";
      case 136:
        return "Payment enabled, Pass enabled";
      case 128:
        return "Payment enabled";
      case 12:
        return "Pass enabled and requested";
      case 8:
        return "Pass enabled";
      default:
        throw new SmartTapException("Bad transaction mode.");
    }
  }
}
