package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.alias.Alias;
import org.example.service.Decrypter;
import org.example.service.Encrypter;

import java.security.Security;

import static org.example.utils.GeneratorUtils.xorOfRandom;

public class Main {
    /*
    * Main application acting as the internet
    * */
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Alias suresh = new Alias("Sunita"); // sender
        Alias ramesh = new Alias(); // receiver

        // Suresh wants to tell ramesh about his crush in work place but doesn't want anyone to know.
        // Suresh asks ramesh to send his randomString and public key
        String rameshPublicKey = ramesh.getPublicKey();
        String rameshRandomString = ramesh.getRandomString();

        // Suresh encrypts the crushName using his private key and ramesh's public key along with xor of random String
        String encryptName = Encrypter.encrypt(xorOfRandom(suresh.getRandomString(), rameshRandomString),
                suresh.getPrivateKey(), rameshPublicKey, suresh.getCrushName());

        // Now Suresh sends the name to ramesh along with randomString and suresh's public key
        String sureshPublicKey = suresh.getPublicKey();
        String sureshRandomString = suresh.getRandomString();
        String decryptName = Decrypter.decrypt(xorOfRandom(ramesh.getRandomString(), sureshRandomString),
                ramesh.getPrivateKey(), sureshPublicKey, encryptName);
        System.out.println("=====> Ramesh decrypted, Suresh's crush Name: " + decryptName);

        // Shyam was watching them and wanted to know about suresh's crush so he also tried to decrypt the data.
        Alias shyam = new Alias();
        String shyamDecryptName = Decrypter.decrypt(xorOfRandom(shyam.getRandomString(), sureshRandomString),
                shyam.getPrivateKey(), sureshPublicKey, encryptName);
        System.out.println("=====> Shyam decrypted, Suresh's crush Name: " + shyamDecryptName);
    }
}