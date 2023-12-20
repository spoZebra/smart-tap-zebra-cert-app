package com.google.smarttapsample;

import android.nfc.NdefMessage;

/**
 * --- spoZebra BEGIN ---
 * Issue get additional smart tap data which was missing
 */
public class GetAdditionalDataCommand {

    private static final byte[] COMMAND_PREFIX = new byte[]{
            (byte) 0x90,
            (byte) 0xC0,
            (byte) 0x00,
            (byte) 0x00
    };

    GetAdditionalDataCommand() {
        //The get additional smart tap data command has no data payload.
    }

    /**
     * Converts an instance of this class into a byte-array `get smart tap data` command
     *
     * @return A byte array representing the command to send
     */
    byte[] commandToByteArray() throws Exception {
        try {
            return Utils.concatenateByteArrays(
                    COMMAND_PREFIX,
                    new byte[]{(byte) 0x00});
        } catch (Exception e) {
            throw new SmartTapException(
                    "Problem turning `get smart tap data` command to byte array: " + e);
        }
    }
}
/**
 * --- spoZebra END ---
 */
