# openldap-msssha
Microsoft SHA1 support for OpenLDAP with configurable cryptographic salt
----------------------
pw-msssha.c provides support for Microsoft SHA1 password hashes in OpenLDAP.

About msssha
------------
The main difference beetween standart OpenLDAP SHA1 and Microsoft salted SHA1 in salt order.
Microsoft add password to salt. And there is way to change this behaviour in standart module in OpenLDAP. 

A msssha hash in OpenLDAP looks like this:

{MSSSHA}b3i38Rzua74KoRiyLcnC/I2U1d0=

- {MSSSHA} is the name of the scheme
- other part is hash 

Building
--------
1) Build and install OpenLDAP itself from the root of the distribution or
from a main source. Add dependencies.

apt-get update
apt-get install wget make libsasl2-dev python-dev libldap2-dev libssl-dev groff groff-base
cd /usr/include
wget https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.4.44.tgz
tar -xvf openldap-2.4.44.tgz
cd openldap-2.4.44

$ ./configure --prefix=/usr/local --enable-modules [other options you want]
$ make depend
$ make
$ sudo make install

2) Incorporate the msssha module in the source directory

$ cd contrib/slapd-modules/passwd
$ git clone <this repo> msssha
$ cd msssha

3) Optional: Customize your setup

- Edit salt variable in Makefile.msssha, like this:
DEFS = -DSALT_TO_USE=\"KpPvknK6CUiB1az6NWmG\+g==\" 

4) Build the msssha module:

$ make -f Makefile.msssha
$ sudo make install

This will install the module to {prefix}/libexec/openldap/

5) Edit your slapd.conf, and add:

moduleload /usr/local/libexec/openldap/pw-msssha.so
 
If you want all your new hashes to use msssha (in Password Modify Extended
Operations), set this in your slapd.conf:

password-hash   {MSSSHA}

However, make sure that all LDAP servers in your environment have the module
loaded before you do this, otherwise your users will not be able to authenticate.

You could use modern approach to configurate OpenLDAP changing cn=config. This is preferable approach.

6) Restart slapd (if you have used slapd.conf file)

Testing
-------
Use slappasswd to generate some hashes.

$ slappasswd -h '{MSSHA}' -o module-load="<path-to-the-module>/pw-msssha.so" -s randompassword

(Yes, the keyword here is 'module-load' with a - (dash). In slapd.conf the
keyword is 'moduleload' without the dash.) 
