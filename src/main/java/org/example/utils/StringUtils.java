package org.example.utils;

import org.bouncycastle.util.encoders.Base64;

public class StringUtils {
    public static String getBase64String(byte[] value) {
        return new String(Base64.encode(value));
    }

    public static byte[] getBytesForBase64String(String value){
        return org.bouncycastle.util.encoders.Base64.decode(value);
    }
}
