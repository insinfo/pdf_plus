baixado de https://www.gov.br/iti/pt-br/assuntos/navegadores/java/versao-windows

https://www.gov.br/inpi/pt-br/composicao/seguranca-da-informacao/arquivos/CartilhaDISEGInstruesparaInstalaodaCadeiaCertificadoradaICPBrasil.pdf

https://www.tre-al.jus.br/institucional/cadeia-de-certificados-icp-brasil-v5

https://certisign.com.br/suporte/download/hierarquia-de-certificacao/icp-brasil/br

Versão Windows
Compartilhe:  Compartilhe por Facebook Compartilhe por Twitter Compartilhe por LinkedIn Compartilhe por WhatsApplink para Copiar para área de transferência
Publicado em 08/12/2021 08h39 Atualizado em 01/12/2025 16h05
ATUALIZAÇÃO DA CADEIA DE CERTIFICADOS DA ICP-BRASIL NO JAVA - WINDOWS

Passo 1: Atualize o Java comforme seção anterior.

Passo 2: Clique para baixar a Keystore ICP-Brasil.

Passo 3: Descompactar o arquivo (keystore_icp_brasil-jks.zip) no desktop.

Passo 4: No módulo administrador, acesse prompt de comando e utilize modo de importação, conforme as especificações do seu sistema operacional


"C:\Program Files\Java\jre1.8.0_40\bin\keytool.exe" -importkeystore -srckeystore "C:\Users\nome_do_usuário\Desktop\keystore_ICP_Brasil.jks" -srcstorepass 12345678 -destkeystore "C:\Program Files\Java\jre1.8.0_40\lib\security\cacerts" -deststorepass changeit 

Obs.: Utilize "C:\Program Files (x86)\ ..." caso seu sistema de arquivo seja 64 bits

Pronto! A cadeia de certificados ICP-Brasil já está pronta para a utilização java.
