package Practica1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
 
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EmpaquetarFactura {

    // Nombres de los bloques dentro del Paquete
    public static final String BLOQUE_FACTURA_CIFRADA = "FACTURA_CIFRADA";
    public static final String BLOQUE_IV = "IV";
    public static final String BLOQUE_CLAVE_CIFRADA = "CLAVE_CIFRADA";
    public static final String BLOQUE_FIRMA_EMPRESA = "FIRMA_EMPRESA";
    // Tamaño de la clave AES en bits.
    private static final int TAMANO_CLAVE_AES = 128;
    private static final String TRANSFORMACION_AES = "AES/CBC/PKCS5Padding";
    private static final String TRANSFORMACION_RSA = "RSA/ECB/PKCS1Padding";
    private static final String ALGORITMO_FIRMA = "SHA256withRSA";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (args.length != 4){
            System.out.println("Uso: java EmpaquetarFactura <ruta_factura> <nombre_fichero_salida> <ruta_clave_publica_Hacienda> <ruta_clave_privada_Empresa>");
            System.exit(1);
        }
        String ficheroFactura = args[0];
        String nombrePaquete = args[1];
        String ficheroClavePublicaHacienda = args[2];
        String ficheroClavePrivadaEmpresa = args[3];

        try{
            Security.addProvider(new BouncyCastleProvider());

            // Leer el fichero de la factura.
            byte[] facturaClara = Files.readAllBytes(Paths.get(ficheroFactura));

            // Generar una clave AES de sesión aleatoria.
            KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
            kg.init(TAMANO_CLAVE_AES);
            SecretKey claveAES = kg.generateKey();

             //  Cifrar la Factura con AES/CBC. El IV se genera solo y hay
            //    que guardarlo
            Cipher cifradorAES = Cipher.getInstance(TRANSFORMACION_AES, "BC");
            cifradorAES.init(Cipher.ENCRYPT_MODE, claveAES);
            byte[] iv = cifradorAES.getIV();
            byte[] facturaCifrada = cifradorAES.doFinal(facturaClara);

             //  Cifrar la clave AES con la clave pública RSA de Hacienda.
            byte[] bytesClavePublica = Files.readAllBytes(Paths.get(ficheroClavePublicaHacienda));
            X509EncodedKeySpec specClavePublica = new X509EncodedKeySpec(bytesClavePublica);
            KeyFactory fabricaClaves = KeyFactory.getInstance("RSA");
            PublicKey clavePublicaHacienda = fabricaClaves.generatePublic(specClavePublica);

            Cipher cifradorRSA = Cipher.getInstance(TRANSFORMACION_RSA, "BC");
            cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublicaHacienda);
            byte[] claveAESCifrada = cifradorRSA.doFinal(claveAES.getEncoded());

            //Firmar la factura con la clave privada de la empresa
             byte[] bytesClavePrivadaEmpresa = Files.readAllBytes(Paths.get(ficheroClavePrivadaEmpresa));
            PKCS8EncodedKeySpec specClavePrivada = new PKCS8EncodedKeySpec(bytesClavePrivadaEmpresa);
            PrivateKey clavePrivadaEmpresa = fabricaClaves.generatePrivate(specClavePrivada);
 
            ByteArrayOutputStream mensajeAFirmar = new ByteArrayOutputStream();
            mensajeAFirmar.write(facturaCifrada);
            mensajeAFirmar.write(iv);
            mensajeAFirmar.write(claveAESCifrada);
 
            Signature firmante = Signature.getInstance(ALGORITMO_FIRMA, "BC");
            firmante.initSign(clavePrivadaEmpresa);
            firmante.update(mensajeAFirmar.toByteArray());
            byte[] firmaEmpresa = firmante.sign();


             // Construir el Paquete con los tres bloques y escribirlo.
            Paquete paquete = new Paquete();
            paquete.anadirBloque(BLOQUE_FACTURA_CIFRADA, facturaCifrada);
            paquete.anadirBloque(BLOQUE_IV, iv);
            paquete.anadirBloque(BLOQUE_CLAVE_CIFRADA, claveAESCifrada);
            paquete.anadirBloque(BLOQUE_FIRMA_EMPRESA, firmaEmpresa);
            paquete.escribirPaquete(nombrePaquete);

             } catch (IOException e) {
                System.err.println("Error de E/S: " + e.getMessage());
                System.exit(2);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                System.err.println("Error al cargar la clave publica de Hacienda: " + e.getMessage());
                System.exit(3);
            } catch (Exception e) {
                System.err.println("Error al empaquetar la factura: " + e.getMessage());
                e.printStackTrace();
                System.exit(4);
        }



        }
    }
    

