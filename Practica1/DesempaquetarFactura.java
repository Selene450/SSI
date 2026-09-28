package Practica1;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarFactura {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println(
                    "Uso: java DesempaquetarFactura <ruta_paquete> <nombre_fichero_factura> <clave_privada_Hacienda>");
            System.exit(1);
        }

        String nombrePaquete = args[0];
        String nombreFicheroFactura = args[1];
        String ficheroClavePrivadaHacienda = args[2];

        try{
            Security.addProvider(new BouncyCastleProvider());

            //Leer paquete
            Paquete paquete = new Paquete(nombrePaquete);
            paquete.leerPaquete(nombrePaquete);

            // Recuperar los bloques del paquete
            byte[] facturaCifrada = paquete.getContenidoBloque("FACTURA_CIFRADA");
            byte[] iv = paquete.getContenidoBloque("IV");
            byte[] claveCifrada = paquete.getContenidoBloque("CLAVE_CIFRADA");

            // Cargar la clave privada de Hacienda desde el fichero
            PKCS8EncodedKeySpec specClavePrivada = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(ficheroClavePrivadaHacienda)));
            KeyFactory fabricaClaves = KeyFactory.getInstance("RSA");

            //DEscifrar la clave AES con la clave privada RSA de Hacienda
            Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cifrador.init(Cipher.DECRYPT_MODE, fabricaClaves.generatePrivate(specClavePrivada));
            byte[] claveAES = cifrador.doFinal(claveCifrada);

            // Descifrar la factura con AES/CBC
            SecretKeySpec claveAESSpec = new SecretKeySpec(claveAES, "AES");
            Cipher cifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cifradorAES.init(Cipher.DECRYPT_MODE, claveAESSpec, ivSpec);
            byte[] facturaDescifrada = cifradorAES.doFinal(facturaCifrada);

            // Guardar la factura descifrada en el fichero de salida
            Files.write(Paths.get(nombreFicheroFactura), facturaDescifrada);

        }catch (Exception e){
            System.err.println("Error desempaquetando la factura: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }

        
    }

}
