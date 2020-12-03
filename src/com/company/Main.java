package com.company;

import java.io.FileInputStream;
import java.security.*;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {

        String keystorePath = "/home/dam2a/.keystore";
        String keystorePassword = "123Dam456";
        char[] passwordChar = keystorePassword.toCharArray();

        Scanner input = new Scanner(System.in);

        // 1
        KeyPair keypair = Cifrar.randomGenerate(1024);
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();


        /*/System.out.print("Introduzca el texto a cifrar: ");
        String texto = input.nextLine();
        byte[] prueba = texto.getBytes();

        byte[] cifrar = Cifrar.encryptData(prueba, publicKey);
        System.out.println(cifrar);

        byte[] descifrar = Cifrar.decryptData(cifrar, privateKey);
        System.out.println(new String(descifrar));/*/

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

    }
}
