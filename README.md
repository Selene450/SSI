## Práctica 1
Se trata de desarrollar una colección de herramientas para el empaquetado y distribución de Facturas
Electrónicas que sea fiable y segura y garantice las restricciones de entrega en los plazos estipulados por
Hacienda.
- Para implementar estas restriciciones de entrega se contará con una especie de Autoridad de sellado de
tiempo simplificada
- Las Empresas podrán generar su Factura Empaquetada a partir de una de sus Facturas. Esta Factura
Empaquetada será remitida a la Autoridad de sellado, que verificará la identidad de la Empresa que ha
remitido la Factura Empaquetada y le vinculará el timestamp (sello de tiempo) que permita verificar la
fecha de entrega.
- Finalmente, el personal de Hacienda podrá validar esta Factura Empaquetada para verificar que procede
de la Empresa correspondiente, extraer la Factura original remitida por la Empresa y validar la
autenticidad del ”sello de tiempo” emitido por la Autoridad de sellado.

#### Simplificaciones
Dado que se trata de una aplicación ”de juguete” se asumirán una serie de simplificaciones.

1. Cada uno de los participantes (Empresa, Autoridad de sellado, Hacienda) podrá generar sus propios pares
de claves privada y pública, que se almacenarán en ficheros simples (no se consideran mecanismos
adicionales de protección del fichero con la clave privada, como sí ocurriría en una aplicación real)
2. No se contemplan los mecanismos de distribución fiable de claves públicas. Se asumirá que todas las
claves públicas necesarias estarán en poder del usuario que las necesite (Empresa, Autoridad de sellado,
Hacienda) de forma confiable (en una aplicación real se haría uso de Certificados Digitales y de una
Autoridad Certificadora común)
