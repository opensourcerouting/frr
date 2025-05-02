.. _secrets-storage:

*******
Secrets
*******

In the course of configuring various routing protocols in FRR, Pre-Shared Keys
(PSKs) can be utilized in various places to improve routing control plane
security.  These PSKs need to be configured in FRR, but in some cases it can
be desirable to have a layer of encryption to avoid having cleartext PSKs in
FRR's configuration.  FRR supports loadable modules implementing "keystores"
to hold PSKs.

.. note::

   A password and a PSK are not the same thing; a password is only *verified*
   by the system but not *used* in itself.  Best practice for passwords is to
   salt and hash them.  PSKs cannot be hashed since the system in fact *needs*
   the original PSK to utilize in sending data out.

   The only passwords in FRR are :clicmd:`enable password PASSWORD` for
   privileged vtysh, and the legacy telnet :clicmd:`password PASSWORD`.  The
   latter will be removed along with removal of the telnet interface.  The
   former is likely to be replaced with a YANG/NACM based access control
   approach at some point.

   The keystore infrastructure handles PSKs, not passwords.  **This section is
   not applicable to either of the two password commands and keystore support
   will not be added for them as it is not the correct approach.**  Passwords
   can be salted and hashed with the (misnamed)
   :clicmd:`service password-encryption` command.

.. caution::

   The security goals and non-goals provided are specific to the keystore used.
   Neither the FRRouting developers nor any distributors are making any claims
   of suitability or implying any responsibility about any security function.

   The standard open source ISC/MIT license note applies:

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

PSK References in Configuration
===============================

PSK items in the configuration that support encryption can be recognized by
the presence of a threefold choice of input:

::

   dummy psk-user <LINE|keystore KEYSTORE KEYDATA|input-keystore KEYSTORE PLAINTEXT>

(``dummy psk-user`` is replaced with the specific usage site of a PSK; note
that additional options may also follow after the key input or in parallel to
it.

The three options function as follows:

.. clicmd:: dummy psk-user LINE

   Enter a PSK in plain cleartext.  A PSK configured like this is kept in the
   configuration as-is.

.. clicmd:: dummy psk-user keystore KEYSTORE KEYDATA

   This option refers to a key stored in the given keystore, with ``KEYDATA``
   passed to the keystore to retrieve the PSK.  For most keystores, ``KEYDATA``
   will be the encrypted version of a PSK, but it is also possible to use a
   keystore module that stores PSKs externally and uses a key identifier
   (e.g. a number or name identifying a key) here.  The actual format of
   ``KEYDATA`` depends on the keystore.

.. clicmd:: dummy psk-user input-keystore KEYSTORE PLAINTEXT

   This option is used to feed an unencrypted PSK into some keystore module,
   such that it stores or encrypts the key as needed by the keystore.

   ``input-keystore ...`` will never be seen in the output of
   ``show running-configuration`` and will never be written out to
   ``frr.conf``.  Inputting this command instead results in an instance of
   ``keystore ...`` showing up in the configuration.

   .. important::

      Since encryption-based keystores use a random IV to encrypt the PSK,
      the resulting ``KEYDATA`` can and will be different each time the input
      command is used, even if the plaintext key remains the same.

   .. danger::

      Do not use ``input-keystore ...`` when externally editing or generating
      an ``frr.conf`` and applying it with ``frr-reload.py``.  The PSK will
      be deleted and reentered each time the configuration is updated, which
      will **result in disruptions of operation**.

.. _psk-identifier:

Reference identifier
--------------------

Each configuration opportunity for a PSK also has an associated "identifier"
that is provided to the keystore.  For example, a ``keychain`` item uses
``keychain:"NAME":INDEX``.  The keystore can use this information to
retrieve keys and/or ensure keys cannot be reused in a different context with
different security properties.

The format of the identifier is specified in the documentation for each PSK
usage site, since it may be required to calculate encrypted keys externally.

Some keystores (noted there) use an additional prefix (before the identifier)
with the value ``f0 9f 90 94 46 52 52 6f 75 74 69 6e 67 3a 00 00``
(``"\xf0\x9f\x90\x94FRRouting:\x00\x00"`` - but note some programming
languages support ``\\x`` escapes with more than 2 digits, which is a problem
with ``\x94F``.)

Specific Keystores
==================

Loading a keystore
------------------

Keystores are implemented as loadable modules in FRR and must be specified
on the daemons' command lines with the ``-M`` option.

.. todo::
   
   Autoload keystore modules?  Not much to be saved here by not loading these
   module?

filekey
-------

The ``filekey`` keystore uses symmetric keys stored in an external JSON file
on the file system to encrypt and decrypt PSKs in the configuration.

.. todo::

   Currently called ``syskeys``, ``filekey`` seems better.

Security function
^^^^^^^^^^^^^^^^^

This keystore has the following security goals:

* preventing leaks of PSKs from being shown in on-screen configuration dumps
* providing secrecy for configuration data in transit between systems
  * only provided if the key file is not transferred at the same time
* allowing keys to be entered by untrusted parties
  * only provided  if access to the key file is prevented for these parties
* preventing a key from being reused in a different location (which might use
  the key in a less secure manner) in the same FRR configuration

It has the following **non-goals**:

* preventing key compromise to users having file system read permissions to
  data owned by FRR (note this is not only ``root`` but also any user in the
  ``frr`` group, and possibly more.)
* preventing key compromise when FRR process memory can be accessed (e.g.
  with a debugger)
* preventing key compromise when the entire file system is leaked, including
  the keyfile
* preventing key compromise when the same keyfile (or key therein) is used on
  multiple systems
* preventing key compromise by use of any "simple-password" protocol
  authentication mechanisms that simply send the PSK out on the wire
* preventing key leakage in coredumps

*The above lists are not implied to be exhaustive.*

Usage
^^^^^

This keystore requires a JSON file with the following format:

.. code-block:: json

   {
       "default-key": {
           "cipher": "aes-128-gcm",
           "key": "..."
       }
   }

The ``cipher`` value is an OpenSSL cipher name.  It must refer to an AEAD
algorithm / cipher and mode combination.  Recommendations are:

* ``aes-128-gcm`` (or ``aes-192-gcm`` or ``aes-256-gcm``)

FIXME: ``chacha20-poly1305`` currently not possible (16-byte tag)

Note that block or stream cipher modes (CBC, ECB, XTS, CTR, etc.) do not form
AEAD algorithms and cannot be used.

Accidental (bit-flip or lower/uppercasing) or intentional modifications of the
ciphertext will be rejected due to the authentication tag becoming invalid.

.. todo::

   AEAD ciphers aren't listed by any of the OpenSSL command line calls?
   ``openssl ciphers`` is wrong (TLS ciphers) and ``openssl enc`` explicitly
   excludes AEAD ciphers since the OpenSSL people don't want to pipe
   unauthenticated data...

Data format
^^^^^^^^^^^

The ``KEYDATA`` used by this keystore is formatted as three base64 blobs
prefixed with a ``$`` each::

   $InitializationVector$Context$EncryptedKey

For example::

   key-string keystore filekey $lOtAytsjw2ZWbGFM$a2V5Y2hhaW46ImZvbyI6Mg==$kBZcW9kVqL0=

The function of the components is as follows:

* first block (Initialization Vector) is simply random data, the length of
  which is a property of the ``cipher`` configured for the key.
* second block (Context) is the configuration context identifier as noted in
  :ref:`psk-identifier`.   The additional prefix is used but not printed to
  the configuration (since it is constant).  This value (including the prefix)
  is fed as AEAD AAD to the encryption algorithm.
* third block (EncryptedKey) contains the output of the encryption algorithm,
  including an AEAD authentication tag.

An example Python script to encode and decode these keys can be found in
FRR's ``tools`` directory.

linux-ringkey
-------------

The ``linux-ringkey`` keystore uses symmetric keys stored in in the Linux
Kernel's keyring API (``CONFIG_KEYS``) to encrypt and decrypt PSKs in the
configuration.  The crypto API (AF_ALG) is used to submit data to the kernel,
have the kernel perform the de/encryption and return it back to FRR.

.. caution::

   Only the primary key used to encrypt the PSKs is in the kernel keyring.
   The PSKs themselves remain in FRR configuration and process memory.

The following key types can be used in this context:

* ``user`` - plain moving the key into the kernel.  Read access can be revoked
  with ``keyctl`` after the key has been installed.
* ``logon`` - same as ``user``, but with read access hardcoded disabled.
* ``encrypted`` - the key is moved in and out of the kernel in an encrypted
  form (with another key that must again be in the keyring.)  This is mostly
  used with the "other" key being a ``trusted`` key.
* ``trusted`` -  key managed with some system trust component (TPM, TEE,
  CAAM, DCP, etc.) which is commonly tied into Secure Boot mechanisms.

The advantage of this keystore is that the primary key can be made
inaccessible to FRR itself, remaining in the kernel.

.. todo::

   Currently called ``linux-keyring``, ``linux-ringkey`` seems better.
   ("linux-keyring" sounds like the PSKs themselves are in the kernel.)

.. note::

   This provides the necessary integration to have PSKs only be accessible
   if the system is booted with signed software, but implementing this in a
   secure and reliable manner requires significant external setup that is
   beyond the scope of FRR.

   The PSKs themselves are still decrypted and kept in FRR processes' memory
   in their cleartext form, i.e. can be exfiltrated with debug access or from
   coredumps.

Security function
^^^^^^^^^^^^^^^^^

The security goals and non-goals of this keystore are the same as with
``filekey``, except that the primary key is made harder to recover.

Kernel configuration requirements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following Linux kernel options must be enabled to use this keystore:

* ``CONFIG_KEYS``
* ``CONFIG_CRYPTO_USER``
* ``CONFIG_CRYPTO_USER_API_AEAD``
* one or more AEAD algorithms, e.g.:
  * ``CONFIG_CRYPTO_GCM`` (AES-GCM)
  * ``CONFIG_CRYPTO_CHACHA20POLY1305``

Additionally, the following Linux kernel options are relevant though not
necessarily required:

* ``CONFIG_PERSISTENT_KEYRINGS`` - without this option, the kernel may
  inadvertedly delete FRR's keys when FRR is being restarted.
* ``CONFIG_TRUSTED_KEYS`` and one or more of its suboptions for keys bound to
  platform security
* ``CONFIG_ENCRYPTED_KEYS`` and ``CONFIG_USER_DECRYPTED_DATA``

Usage
^^^^^

keyctl::

   keyctl add user frrconfig KEYKEYKEYKEYKEYK @u
   keyctl id %user:frrconfig

request-keys::

   # not implemented yet

vtysh::

   crypto keystore linux-keyring gcm(aes) id 123456789

.. todo::

   Write this :)

Data format
^^^^^^^^^^^

This keystore uses the same data format as the ``filekey`` store.  If the same
primary key and algorithm are used, encrypted key data is portable between the
two.

.. caution::

   The list of supported algorithms differs between the Linux kernel and
   OpenSSL.  Choosing an algorithm that is only available in one prevents
   portability to the other for obvious reasons.  Avoid "exotic" algorithms
   if this is a (possibly future) concern.

.. caution::

   The CCM cipher mode (e.g. for AES-CCM), which should be usable here, has
   been reported non-working (fails with "Invalid argument") on some kernel
   versions.
