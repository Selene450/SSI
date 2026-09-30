package Practica1;
 
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
 
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
 
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarFactura {

    private static final String BLOQUE_FACTURA_CIFRADA = "FACTURA_CIFRADA";
    private static final String BLOQUE_IV = "IV";
    private static final String BLOQUE_CLAVE_CIFRADA = "CLAVE_CIFRADA";
    private static final String BLOQUE_FIRMA_EMPRESA = "FIRMA_EMPRESA";
 
    private static final String TRANSFORMACION_AES = "AES/CBC/PKCS5Padding";
    private static final String TRANSFORMACION_RSA = "RSA/ECB/PKCS1Padding";
    private static final String ALGORITMO_FIRMA = "SHA256withRSA";
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println(
                    "Uso: java DesempaquetarFactura <ruta_paquete> <nombre_fichero_factura> <clave_privada_Hacienda> <clave_publica_Empresa>");
            System.exit(1);
        }

        String nombrePaquete = args[0];
        String nombreFicheroFactura = args[1];
        String ficheroClavePrivadaHacienda = args[2];
        String ficheroClavePublicaEmpresa = args[3];

        Security.addProvider(new BouncyCastleProvider());

        // Leer paquete
        Paquete paquete = new Paquete(nombrePaquete);
        paquete.leerPaquete(nombrePaquete);

        // Recuperar los bloques del paquete
        byte[] facturaCifrada = paquete.getContenidoBloque(BLOQUE_FACTURA_CIFRADA);
        byte[] iv = paquete.getContenidoBloque(BLOQUE_IV);
        byte[] claveCifrada = paquete.getContenidoBloque(BLOQUE_CLAVE_CIFRADA);
        byte[] firmaEmpresa = paquete.getContenidoBloque(BLOQUE_FIRMA_EMPRESA);

        if (facturaCifrada == null || iv == null || claveCifrada == null || firmaEmpresa == null) {
            System.err.println("El paquete esta incompleto: faltan bloques ("
                    + BLOQUE_FACTURA_CIFRADA + ", " + BLOQUE_IV + ", " + BLOQUE_CLAVE_CIFRADA
                    + " o " + BLOQUE_FIRMA_EMPRESA + ").");
            System.exit(2);
        }

        // Verificar firma de la empresa antes de descifrar la factura
        try {
            byte[] bytesClavePublicaEmpresa = Files.readAllBytes(Paths.get(ficheroClavePublicaEmpresa));
            X509EncodedKeySpec specClavePublica = new X509EncodedKeySpec(bytesClavePublicaEmpresa);
            PublicKey clavePublicaEmpresa = KeyFactory.getInstance("RSA", "BC").generatePublic(specClavePublica);

            ByteArrayOutputStream mensajeFirmado = new ByteArrayOutputStream();
            mensajeFirmado.write(facturaCifrada);
            mensajeFirmado.write(iv);
            mensajeFirmado.write(claveCifrada);

            Signature verificador = Signature.getInstance(ALGORITMO_FIRMA, "BC");
            verificador.initVerify(clavePublicaEmpresa);
            verificador.update(mensajeFirmado.toByteArray());

            if (!verificador.verify(firmaEmpresa)) {
                System.err.println("FIRMA DE LA EMPRESA NO VALIDA: el paquete no procede de "
                        + "la Empresa correspondiente o ha sido modificado. No se descifra la factura.");
                System.exit(7);
            }
            System.out.println("Firma de la Empresa verificada correctamente.");
        } catch (IOException e) {
            System.err.println("No se puede leer la clave publica de la Empresa: " + e.getMessage());
            System.exit(3);
        } catch (GeneralSecurityException e) {
            System.err.println("Error al verificar la firma de la Empresa: " + e.getMessage());
            System.exit(3);
        }

        try {
            // Cargar la clave privada de Hacienda desde el fichero
            byte[] bytesClavePrivadaHacienda = Files.readAllBytes(Paths.get(ficheroClavePrivadaHacienda));
            PKCS8EncodedKeySpec specClavePrivada = new PKCS8EncodedKeySpec(bytesClavePrivadaHacienda);
            KeyFactory fabricaClaves = KeyFactory.getInstance("RSA", "BC");
            PrivateKey clavePrivadaHacienda = fabricaClaves.generatePrivate(specClavePrivada);

            // Descifrar la clave AES con la clave privada RSA de Hacienda
            Cipher cifrador = Cipher.getInstance(TRANSFORMACION_RSA, "BC");
            cifrador.init(Cipher.DECRYPT_MODE, clavePrivadaHacienda);
            byte[] claveAES = cifrador.doFinal(claveCifrada);

            // Descifrar la factura con AES/CBC
            SecretKeySpec claveAESSpec = new SecretKeySpec(claveAES, "AES");
            Cipher cifradorAES = Cipher.getInstance(TRANSFORMACION_AES, "BC");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cifradorAES.init(Cipher.DECRYPT_MODE, claveAESSpec, ivSpec);
            byte[] facturaDescifrada = cifradorAES.doFinal(facturaCifrada);

            // Guardar la factura en claro.
            Files.write(Paths.get(nombreFicheroFactura), facturaDescifrada);
            System.out.println("Factura descifrada y guardada en: " + nombreFicheroFactura);
        } catch (IOException e) {
            System.err.println("No se puede leer la clave privada de Hacienda: " + e.getMessage());
            System.exit(3);
        } catch (GeneralSecurityException e) {
            System.err.println("Error al cargar la clave privada de Hacienda: " + e.getMessage());
            System.exit(3);
        } catch (Exception e) {
            System.err.println("Error desempaquetando la factura: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
