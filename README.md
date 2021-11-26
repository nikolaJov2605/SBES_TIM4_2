# SBES_TIM4_2

Projektni zadatak 2.

Implementirati komponentu za upravljanje servisima (Service Management - SM) u okviru koje
je moguće pokretati i zaustavljati servise. Sastavni deo SM komponente je blacklist konfiguracija
koja definiše spisak zabranjenih portova i/ili protokola koji smeju da budu aktivni za određene
grupe korisnika. Sve nedozvoljene pokušaje startovanja servisa SM loguje u okviru posebne
Audit komponente sa kojom uspostavlja komunikaciju preko sertifikata.
Prilikom uspostavljanja komunikacije između SM sa klijentima, vrši se Windows autentifikacija,
dok je autorizacija zasnovana na RBAC modelu.
● Prvi korak u komunikaciji sa SM je uvek razmena ključa sesije – pozivom metode
Connect, koju klijent može pozvati ukoliko ima privilegiju ExchangeSessionKey.
● Sledeći korak je poziv metode za startovanje servisa pod nalogom klijenta koji inicira
njihovo startovanje - ukoliko klijent ima privilegiju RunService.
● Prilikom startovanja servisa, klijent prosleđuje neophodne parametre: ime mašine, port,
protokol koje kriptuje primenom AES algoritma u CBC modu (ugrađeni .NET
mehanizam) koristeći ključ sesije kao tajni ključ.
● Servis dekriptuje pristiglu poruku i u zavisnosti od blacklist konfiguracije startovanje
servisa se dozvoljava ili ne dozvoljava.
Dodatno, Audit komponenta treba da obezbedi detekciju Denial of Service (DoS) napada. DoS
napad je svaka detekcija da isti klijent pokušava više od unapred definisanog broja pokušaja (u
određenom vremenskom periodu) da otvori isti port ili komunicira po istom protokolu koji je
zabranjen blacklist konfiguracijom.
Posebna grupa SM klijenata ima pravo da menja blacklist konfiguraciju, odnosno da periodično
proverava da li je narušen integritet fajla gde se konfiguracija skladišti. Validna izmena
konfiguracije je izmena napravljena posredstvom SM komponente koja računa checksum za dati
fajl (te je svaka ručna izmena neovlašćena). U slučaju da je integritet narušen, SM prijavljuje
događaj Audit komponenti i nakon toga se zaustavlja.
