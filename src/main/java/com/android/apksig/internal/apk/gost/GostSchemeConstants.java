package com.android.apksig.internal.apk.gost;

/** Constants used by the Signature Scheme signing and verification. */
public class GostSchemeConstants {
    private GostSchemeConstants() {}

    public static final int APK_SIGNATURE_GOST_SCHEME_BLOCK_ID = 0x2f02bfc7; // first_4_bytes(sha-256("cryptopro"))
}
