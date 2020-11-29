# DigiSign

Repo sisaldab saatja ja vastuvõtja vahelist protokolli (kokkulepet) edastatava andmefaili allkirjastamiseks, koos teostusnäitega (POC).  

## Protokoll

1  Saatja allkirjastab andmefaili elliptilise kõvera allkirjaalgoritmiga (Elliptic Curve Digital Signature Algorithm), vastavalt standardile FIPS 186-3.

2  Saatja salvestab allkirja ASN.1 DER-formaadis faili. Allkirjafaili nimi koosneb allkirjastatud andmefaili nimest, millest failitüüp (nime lõpus olev punktiga eraldatud osa) on asendatud failitüübiga `.sign`.

3  Saatja edastab andmefailiga koos allkirjafaili.

4  Allkirjastamisel kasutatud privaatvõtmele vastava avaliku võtme edastab saatja vastuvõtjale taustakanali kaudu. Avalik võti edastatakse PEM-formaadis failina; faili nimi on `publickey.pem`.

5  Allkirjastamisel kasutatav võtmepaar genereeritakse 2 aastaks.

6  Privaatvõtme kompromiteerumisel, kompromiteerumise kahtluse korral või 2-aastase perioodi lõppemisel genereerib saatja uue võtmepaari ja edastab uue avaliku võtme vastuvõtjale.

## POC

Protokolli kontseptsioonitõendusena (POC) on kaustas kolmest rakendusest koosnev komplekt.

Rakendus `createkey` genereerib ECDSA võtmepaari ja salvestab selle X.509 PEM failidesse `privatekey.pem` ja `publickey.pem`.

Rakendus `sign` loeb failist `privatekey.pem` sisse ECDSA privaatvõtme, allkirjastab selle võtmega faili `data.txt` ja salvestab allkirja faili `data.sign`.

Rakendus `verify` loeb failist `publickey.pem` sisse ECDSA avaliku võtme, seejärel loeb sisse andmefaili `data.txt` ja allkirjafaili `data.sign` ning kontrollib allkirja. Kontrolli tulemuse väljastab konsoolile.

Rakenduste ehitamine (repo peakaustast):

````
go build ./createkey
go build ./sign
go build ./verify
````

Rakenduste käivitamine (Windows):

````
createkey
sign
verify.exe
````

Rakenduste käivitamine (Linux):

````
./createkey
./sign
./verify
````

Allkirjafaili formaati saab soovi kontrollida ka käsurealt OpenSSL abil:

`openssl asn1parse -inform DER -in data.sign`.
