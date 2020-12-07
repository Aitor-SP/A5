package com.company;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {

        String keystorePath = "D:\\Usuarios\\Aitor\\Documents\\DAM\\2 DAM\\M03 - Programació bàsica\\PROYECTOS\\A5\\src\\com\\company\\.keystore";
        String keystorePassword = "123Dam456";
        char[] passwordChar = keystorePassword.toCharArray();
        String cerPath = "D:\\Usuarios\\Aitor\\Documents\\DAM\\2 DAM\\M03 - Programació bàsica\\PROYECTOS\\A5\\src\\com\\company\\jordi.cer";

        Scanner input = new Scanner(System.in);

        // 1
        KeyPair keypair = Cifrar.randomGenerate(1024);
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        System.out.print("Introduzca el texto a cifrar: ");
        String texto = input.nextLine();
        byte[] prueba = texto.getBytes();

        byte[] cifrar = Cifrar.encryptData(prueba, publicKey);
        System.out.println(cifrar);

        byte[] descifrar = Cifrar.decryptData(cifrar, privateKey);
        System.out.println("Texto descifrado: "+new String(descifrar));

        // 2
        // 2.1
        System.out.println("Tipo de Keystore: "+Cifrar.loadKeyStore(keystorePath,keystorePassword).getType());

        // 2.2
        System.out.println("Tamaño de la Keystore: "+Cifrar.loadKeyStore(keystorePath,keystorePassword).size());

        // 2.3
        System.out.println("Alias de la Keystore: "+ Cifrar.loadKeyStore(keystorePath,keystorePassword).aliases().nextElement());

        // 2.4
        System.out.println("Certificado de la clave: "+Cifrar.loadKeyStore(keystorePath,keystorePassword).getCertificate("lamevaclaum9"));

        // 2.5
        System.out.println("Algoritmo cifrado de la clave: "+Cifrar.loadKeyStore(keystorePath,keystorePassword).getCertificate("lamevaclaum9").getPublicKey().getAlgorithm());

        // 2.ii
        SecretKey claveSimetrica = Cifrar.keygenKeyGeneration(128);
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(claveSimetrica);
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keystorePassword.toCharArray());
        KeyStore ks = Cifrar.loadKeyStore(keystorePath, keystorePassword);
        ks.setEntry("nuevaKey", skEntry, protParam);

        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream("newKeyStoreName");
            ks.store(fos, passwordChar);
        } finally {
            if (fos != null) {
                fos.close();
            }
        }

        Enumeration<String> aliases = ks.aliases();
        System.out.print("Alias de las claves: ");
        while(aliases.hasMoreElements()){
            System.out.print(aliases.nextElement()+"  ");
        }

        // 3
        System.out.println(Cifrar.getPublicKey(cerPath));

        // 4
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try(InputStream keyStoreData = new FileInputStream(keystorePath)){
            keyStore.load(keyStoreData, passwordChar);
        }
        System.out.println(Cifrar.getPublicKey(keyStore,"lamevaclaum9",keystorePassword));

        // 5
        byte[] texto1 ="prueba".getBytes();
        System.out.println("Firma :"+ new String(Cifrar.signData(texto1,privateKey)));

        // 6
        byte[] firma = Cifrar.signData(texto1,privateKey);
        System.out.println("Validez: "+Cifrar.validateSignature(texto1, firma, publicKey));

        // 2.2
        String texto2 = "final";
        byte[] data = texto2.getBytes();

        byte[][] cifrado = Cifrar.encryptWrappedData(data,publicKey);
        System.out.println("Texto cifrado :"+cifrado);


        System.out.println("Texto descifrado :" + new String(Cifrar.decryptWrappedData(cifrado,privateKey)));
    }
}
