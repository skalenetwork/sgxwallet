sgxwallet: billetera criptográfica de hardware basada en SKALE SGX
Discordia

Intro
sgxwallet es una billetera criptográfica segura de hardware de próxima generación que se basa en la tecnología Intel SGX . Actualmente es compatible con Ethereum y SKALE , y admitirá Bitcoin en el futuro.

sgxwallet se ejecuta como servidor de red. Los clientes se conectan al servidor, se autentican en él mediante el protocolo TLS 1.0 con certificados de cliente y luego envían solicitudes al servidor para generar claves criptográficas y realizar operaciones criptográficas. Las claves se generan dentro del enclave seguro de SGX y nunca dejan el enclave sin cifrar.

El servidor proporciona un servicio de registro inicial para emitir certificados de cliente a los clientes. El administrador aprueba manualmente cada registro.

sgxwallet ha sido probado en Ubuntu Linux 18.04 .

Una nota importante sobre la preparación para la producción
El servidor sgxwallet todavía está en desarrollo activo y, por lo tanto, debe considerarse como software alfa . El desarrollo aún está sujeto a un endurecimiento de la seguridad, más pruebas y cambios importantes. Este servidor aún no ha sido revisado ni auditado por seguridad. Consulte SECURITY.md para conocer las políticas de informes.

Construya, pruebe y empuje el contenedor sgxwallet Construya, pruebe y envíe un contenedor en modo sim

Ejecutando sgxwallet
Clonar este repositorio
Como probablemente sospecha, lo primero que debe hacer es clonar este repositorio y todo lo que son subdepositorios.

clon de git https://github.com/skalenetwork/sgxwallet.git --recurse-submodules
Prueba en modo simulación
La forma más sencilla de probar el servidor sgxwallet es ejecutar un contenedor docker en modo de simulación inseguro que emule un procesador SGX. Una vez que esté familiarizado con el servidor, puede habilitar sgx en su máquina y ejecutarlo en modo de producción seguro.

Primero instale docker-compose si no lo tiene

sudo apt-get install docker.io docker-compose
Luego ejecute sgxwallet usando docker-compose

cd run_sgx_sim ; sudo docker-compose up
Nota: necesita una máquina que admita el conjunto de instrucciones Intel AVX512. La mayoría de las CPU Intel modernas lo admiten. Para verificar que su máquina sea compatible con AVX512, ejecute

cat /proc/cpuinfo | grep avx512
Nota: sgxwallet requiere docker-compose para su correcto funcionamiento. Siempre debe usar docker-compose y evitar el uso de herramientas de docker sin procesar.

Nota: el modo de simulación es solo para probar sgxwallet. En producción, debe ejecutar sgxwallet en un servidor que admita SGX. Nunca ejecute un sgxserver de producción en modo de simulación.

Guía de administración
Si es un validador de SKALE y desea ejecutar sgxwallet para el uso de testnet o mainnet, necesita un servidor compatible con SGX.
Consulte la guía de administración para obtener detalles sobre cómo configurar sgxwallet en un modo de hardware seguro docs / admin-guide.md .

Guía para desarrolladores
Si es un desarrollador de SKALE y desea compilar sgxwallet desde la fuente, consulte la guía del desarrollador docs / developer-guide.md .

Contribuyendo
Consulte Contribución para obtener información sobre cómo contribuir.

Bibliotecas utilizadas por este proyecto
Intel-SGX-SSL de Intel
LevelDB de Google
libBLS por SKALE Labs
libff por SCIPR-LAB
Controlador Linux SGX de Intel
SGX-GMP de Intel
Software SGX habilitado por Intel
Licencia
Licencia

Todas las contribuciones a sgxwallet se realizan bajo la GNU Affero General Public License v3 . Ver LICENCIA .

Copyright (C) 2019-Presente SKALE Labs.
