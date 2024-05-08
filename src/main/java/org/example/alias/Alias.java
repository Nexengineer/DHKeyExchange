package org.example.alias;

import org.example.utils.GeneratorUtils;
import org.example.utils.KeyUtils;


import java.security.*;

import static org.example.utils.StringUtils.getBase64String;

public class Alias {
    private KeyPair keyPair;
    private String randomString;
    private String crushName;

    public Alias(String crushName) {
        try {
            this.keyPair = GeneratorUtils.generateKeyPair();
            this.randomString = GeneratorUtils.generateRandomKey();
            this.crushName = crushName;
        } catch (Exception exception) {
            System.out.println("Exception caused: " + exception.getLocalizedMessage());
        }
    }

    public Alias() {
        this("");
    }

    public String getPublicKey() throws Exception {
        byte[] encodedPublicKey = KeyUtils.getEncodedPublicKey(keyPair.getPublic());
        return getBase64String(encodedPublicKey);
    }

    public String getPrivateKey() throws Exception {
        byte[] encodedPrivateKey = KeyUtils.getEncodedPrivateKey(keyPair.getPrivate());
        return getBase64String(encodedPrivateKey);
    }

    public String getRandomString() {
        return randomString;
    }

    public String getCrushName() {
        return crushName;
    }
}
