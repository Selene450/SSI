package Practica1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
import java.time.Instant;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarFactura {

    private static final String BLOQUE_FACTURA_CIFRADA = "FACTURA_CIFRADA";
    private static final String BLOQUE_IV = "IV";
    private static final String BLOQUE_CLAVE_CIFRADA = "CLAVE_CIFRADA";
    private static final String BLOQUE_FIRMA_EMPRESA = "FIRMA_EMPRESA";
    private static final String BLOQUE_SELLO_TIEMPO = "SELLO_TIEMPO";
    private static final String BLOQUE_FIRMA_AUTORIDAD = "FIRMA_AUTORIDAD";

    private static final String ALGORITMO_FIRMA = "SHA256withRSA";
    
    public static void main(String[] args) {
        if(args.length != 3){
            System.out.println("Uso: java SellarFactura <nombre_paquete> <ruta_clave_publica_empresa> <ruta_clave_privada_autoridad>");
            System.exit(1);
        }

        String nombrePaquete = args[0];
        String rutaClavePublicaEmpresa = args[1];
        String rutaClavePrivadaAutoridad = args[2];

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

        // Verificar firma de la empresa antes de firmar la factura con la autoridad
        try {
            byte[] bytesClavePublicaEmpresa = Files.readAllBytes(Paths.get(rutaClavePublicaEmpresa));
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

        byte[] selloTiempo = null;
        byte[] firmaAutoridad = null;

        // Firmar la factura con la clave privada de la autoridad
         try {
            byte[] bytesClavePrivadaAutoridad = Files.readAllBytes(Paths.get(rutaClavePrivadaAutoridad));
            PKCS8EncodedKeySpec specClavePrivada = new PKCS8EncodedKeySpec(bytesClavePrivadaAutoridad);
            PrivateKey clavePrivadaAutoridad = KeyFactory.getInstance("RSA", "BC").generatePrivate(specClavePrivada);
 
            // Fecha y hora de sellado, como String UTF-8 (simplificacion
            // 2.1.4 del enunciado: todo dato aportado por un participante
            // viaja como String con codificacion UTF8).
            selloTiempo = Instant.now().toString().getBytes(StandardCharsets.UTF_8);
 
            ByteArrayOutputStream mensajeASellar = new ByteArrayOutputStream();
            mensajeASellar.write(firmaEmpresa);
            mensajeASellar.write(selloTiempo);
 
            Signature firmante = Signature.getInstance(ALGORITMO_FIRMA, "BC");
            firmante.initSign(clavePrivadaAutoridad);
            firmante.update(mensajeASellar.toByteArray());
            firmaAutoridad = firmante.sign();
        } catch (IOException e) {
            System.err.println("No se puede leer la clave privada de la Autoridad: " + e.getMessage());
            System.exit(4);
        } catch (GeneralSecurityException e) {
            System.err.println("Error al firmar la factura con la clave privada de la Autoridad: " + e.getMessage());
            System.exit(4);
        }
 
        // Añadir los dos bloques de sellado al mismo paquete recibido como
        // parametro y volver a escribirlo (mismo fichero, con los bloques
        // nuevos incorporados a los que ya trajera la Empresa).
        paquete.anadirBloque(BLOQUE_SELLO_TIEMPO, selloTiempo);
        paquete.anadirBloque(BLOQUE_FIRMA_AUTORIDAD, firmaAutoridad);
        paquete.escribirPaquete(nombrePaquete);
 
        System.out.println("Factura sellada correctamente. Sello de tiempo: "
                + new String(selloTiempo, StandardCharsets.UTF_8));
 
    }





}

