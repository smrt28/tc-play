About
==========
tcplay is a free (BSD-licensed), pretty much fully featured (including multiple
keyfiles, cipher cascades, etc) and stable TrueCrypt implementation.

This implementation supports mapping (opening) both system and normal TrueCrypt
volumes, as well as opening hidden volumes and opening an outer volume while
protecting a hidden volume. There is also support to create volumes, including
hidden volumes, etc. Since version 1.1, there is also support for restoring
from the backup header (if present), change passphrase, keyfile and PBKDF2
PRF function.

Since tcplay uses dm-crypt (or dm_target_crypt on DragonFly) it makes full use
of any available hardware encryption/decryption support once the volume has been
mapped.

It is based solely on the documentation available on the TrueCrypt website,
many hours of trial and error and the output of the Linux' TrueCrypt client.
As it turns out, most technical documents on TrueCrypt contain mistakes, hence
the trial and error approach.


Yubikey
==========
The goal is to use Yubico stick as a PIN-protected secret provider and use the
secret to derive the TrueCrypt header-key.

It seems there is no proper way to store an arbitrary PIN protected secret on
the Yubikey. Yubikey has just five data slots which are supposed to be holding
PIN protected data. According to PIV spec. any of those slots is not supposed
to carry this type of data. This code is a workaround implementation.

Yubico PIV allows storing RSA2048 keys in several slots. An exact number of the
slots varies on the Yubikey version. There should be about 24 slots available
for this purpose on Yubikey 4 and Yubikey 5. It seems there are just four slots
available on Yubikey NEO. The slots are write-only, the RSA key imported into
the slot can't be read back. The key in Yubikey PIV can be used for decrypting
and signing only, and all those operations are PIN protected.

Sign operation can't be used since it adds random padding to the resulting
signature and we need the secret obtained from the Yubikey to be deterministic.
So the solution is based on the decipher operation.

Before using the Yubikey you have to set up a PIV slot with an RSA2048 key
which Yubikey will use for derive the secret. For instance, you can let
youbikey to generate it for you by itself:

    yubico-piv-tool -a generate -s 82

TcPlay handles Yubikey as a device with a key file on it. Surprisingly you can
pass the key file to TcPlay by the obvious -k argument. To use the PIV secret
derivation approach, the key file name should be in the following format:

//yubikey/piv/[slot]/[nonce]

You can also use HMAC challenge-response approach by passing:

//yubikey/chl/[slot]/[nonce]

Note, HMAC challenge-response doesn't require the PIN.

For instance, to mount the device using Yubikey PIV slot 90 you would use this
command:

tcplay -d /dev/loop10 -m xxx -k //yubikey/piv/90/a


The secret derivation
---------------------

TcPlay uses Yubikey to derive the secret from the nonce within the key file
path. If you enter the yubikey file name without the nonce part like
//yubikey/piv/90, the disk encryption password would be used instead.

PBKF2 with Blake2 hash algorithm and 1000 iterations derives a chunk of 256
bytes (2048 bits) from the nonce.

The very first bit of the chunk is masked out to ensure that the number it
represents, is lower then RSA2048 modulus.

The chunk is passed to the given Yubico slot decipher function which returns
the result of the RSA formula c^d mod m where d is private hidden on Yubikey.
PBKF2 with 10 iterations derives the final secret. The final 512bit secret will
be used as the key file content.

yubico-keyfile
--------------

TcPlay uses Yubikey secret to derive header-key in the same way as
TrueCrypt/tc-play derives header-key from keyi files. The "yubico-keyfile"
utility can obtain the secret from the Yubikey for you and store it in the
file. You can backup the file. It would work as a keyfile as well as your
Yubikey.

yubico-keyfile -s //yubikey/piv/90/a -o ./keyfile

Then those commands would do the same:


# derives secret from the yubikey device
tcplay -d /dev/loop10 -m xxx -k //yubikey/piv/90/a

# reads the same device from the key file
tcplay -d /dev/loop10 -m xxx -k ./keyfile


New algorithm
=============

crypto: CAMELLIA
hashing: Argon2 - needs 1GB memory


Implementation notes
====================
DragonFly BSD uses the hybrid OpenSSL + cryptodev(9) approach that can be
found in crypto-dev.c. OpenSSL is only used for the hash/pbkdf2. The
encryption/decryption is performed via cryptodev(9) with enabled cryptosoft.

On Linux gcrypt is used for the encryption and decryption. For the hash/pbkdf2
either gcrypt or OpenSSL can be used. gcrypt only supports pbkdf2 since its
July 2011 release (1.5.0), while OpenSSL has had pbkdf2 since around December
2010, so its easier to find in most distros.

The crypto options can be chosen with make/Makefile parameters. Building on Linux
is as easy as doing

    make -f Makefile.classic SYSTEM=linux

you can even skip the SYSTEM=linux, since that's the default. To choose the
PBKDF backend, you can use either,

    make -f Makefile.classic PBKDF_BACKEND=openssl

or

    make -f Makefile.classic PBKDF_BACKEND=gcrypt

The interface to device mapper is libdevmapper on Linux and libdm on DragonFly.
libdm is a BSD-licensed version of libdevmapper that I hacked together in a few
hours.

On Ubuntu, the following dev packages are needed to build tcplay:

    apt-get install build-essential libdevmapper-dev libgcrypt11-dev uuid-dev


Following packages are needed to enable Yubico and Argon2 support: 

add-apt-repository ppa:yubico/stable
apt install libykpiv-dev libykpers-1-dev libargon2-0-dev libdevmapper-dev uuid-dev libgcrypt20-dev


Library
==========
In addition to providing a command line tool, tcplay is also available as a
library. See the `tcplay.3` man page for more details on how to use the API.

TODO: link examples


Documentation
==========
Please refer to the man pages bundled with tcplay.



Download for packaging
==========
Latest release can be found as a (source) tarball at:

https://github.com/bwalex/tc-play/archive/v2.0.tar.gz



Bugs
==========
Please report all bugs on the github issue tracker. If appropriate, please
attach a small test volume which you think tcplay isn't handling correctly.
The reduce_test_vol.sh script in test/ can significantly reduce the size
of a volume when compressed by stripping out all the unnecessary data,
leaving only the headers. After that, just bzip2 it and it should be fairly
tiny.

What would be even better is if you could write a small test case to
reproduce the issue. The README in the test/ directory has information on
how to write tests for tcplay.



OS Support
==========
tcplay is now available for both DragonFly BSD and Linux. It is a core part of
the DragonFly BSD operating system and is available in a number of linux
distros.



Licensing
==========
The project is under a two-clause BSD license. I would consider dual-licensing
it if required. Drop me an email to discuss the options.



Development
==========
tcplay is pretty much stable, but if you find a bug, please report it.
If anyone wants to add new features or port it to another OS, I'll gladly merge
your changes into this repository so that there is a single point of contact.

I've noticed that sometimes bugs are only reported downstream (e.g. in the
distro's bugtracker). Please make sure those bugs are also reported upstream on
github, otherwise odds are they will never reach me.



Bugs in the TrueCrypt documentation
==========
The TrueCrypt documentation is pretty bad and does not really represent the
actual on-disk format nor the encryption/decryption process.

Some notable differences between actual implementation and documentation:
 - PBKDF using RIPEMD160 only uses 2000 iterations if the volume isn't a system
   volume.
 - The keyfile pool is not XOR'ed with the passphrase but modulo-256 summed.
 - Every field *except* the minimum version field of the volume header are in
   big endian.
 - Some volume header fields (creation time of volume and header) are missing
   in the documentation.
 - All two-way cipher cascades are the wrong way round in the documentation,
   but all three-way cipher cascades are correct.

