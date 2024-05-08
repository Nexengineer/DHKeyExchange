package org.example.service;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

import static org.example.utils.GeneratorUtils.doECDH;
import static org.example.utils.GeneratorUtils.generateAesKey;
import static org.example.utils.StringUtils.getBase64String;
import static org.example.utils.StringUtils.getBytesForBase64String;

public class Decrypter {
    public static String decrypt(byte[] xorOfRandom, String receiverPrivateKey, String senderPublicKey, String stringToDecrypt) throws Exception {
        // Generating shared secret
        String sharedKey = doECDH(getBytesForBase64String(receiverPrivateKey),getBytesForBase64String(senderPublicKey));
        System.out.println("Shared key: " + sharedKey);

        // Generating iv and HKDF-AES key
        byte[] iv = Arrays.copyOfRange(xorOfRandom, xorOfRandom.length - 12, xorOfRandom.length);
        byte[] aesKey = generateAesKey(xorOfRandom, sharedKey);
        System.out.println("HKDF AES key: " + getBase64String(aesKey));

        // Perform Decryption
        String decryptedData = "";
        try {
            byte[] encryptedBytes = getBytesForBase64String(stringToDecrypt);

            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters =
                    new AEADParameters(new KeyParameter(aesKey), 128, iv, null);

            cipher.init(false, parameters);
            byte[] plainBytes = new byte[cipher.getOutputSize(encryptedBytes.length)];
            int retLen = cipher.processBytes
                    (encryptedBytes, 0, encryptedBytes.length, plainBytes, 0);
            cipher.doFinal(plainBytes, retLen);

            decryptedData = new String(plainBytes);
        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
        }
        return decryptedData;
    }
}
