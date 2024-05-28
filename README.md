
ADDMIN

-------------------------------

Self-sufficient tool for managing administrator accounts on multiple hosts. Allows for adding, blocking and removing 
pre-defined administrators by modifying inventory file. Script creates template files on first run. Also, it 
generates secure ssh-rsa public-private keypair or automatically creates pubkey from provided privkey.

-------------------------------

Requirements:

    pip install bcrypt conson paramiko

-------------------------------

v1.2.5
-added switches to change certain script functions:

    -v, v, --verbose        Prints as much (useful) data as it is possible.
    -i, i, --init           Check files only. Also, performs encryption on passwords in inventory file (if possible). 
    -s, s, --skip-sshd      Do not modify sshd_config file on remote hosts.
    -o, o, --one-by-one     Run operations(threads) on hosts one-by-one, not on all simultaneously.
    -h, h, --help           Shows help message.

v1.2.0

-added function for reading user pubkey from file (subdir users-pubkeys, created automatically);
-added tryout and timeout mechanism when invoking elevated shell;
-added retry mechanism for failed threads;
-changed name of generated/required private and public keys: key.priv, key.pub.

v1.1.3

USAGE

    sudo python3 addmin.py

First run requires user to enter password, which will be key to all encrypted data created by ADDMIN.

After first run, you need to provide all information in 'inventory' file. You can either put your existing private key 
as "key.priv" in ADDMIN workdir or use generated pair. ADDMIN will use host's password to attempt login into target 
machine and export generated pubkey to .ssh/authorized_keys, then it will change sshd_config to prevent authentication
by password.

Defining users without temporary passwords will automatically generate secure temporary password for each, printing
them in console window. If password provided is shorter than 12 characters, it will extend it to required length using
random characters.

Next, all passwords will be encrypted with conson.veil() method with previously entered password as a salt. There will
be prompt which allow to read provided/generated passwords before encrypting them, but only when encryption happens.

Finally, for each host ADDMIN runs separate thread to establish connection and perform desired operations.

-------------------------------

PREFIXES

You can use prefix on username to manage admin account.

Deleting user will require to put exclamation mark ! in front of username in inventory:

        "users": {
            "!username": ["pubkey", "temp_pwd"]
        },

User account will be removed from all hosts defined in inventory.
             
To block user account, you can use hashtag #:

        "users": {
            "#username": ["pubkey", "temp_pwd"]
        },

Blocked user will be unable to log both by sshd (by removing from AllowUsers section of sshd_config), and console.

Note, that users will persist in inventory file - you can easily restore them by removing prefixes.

-------------------------------

ADDITIONAL INFO:

ADDMIN changes sshd_config by setting following parameters:

    Protocol 2
    PermitRootLogin no
    PasswordAuthentiaction no
    AllowUsers

To acquire root privileges, invoked shell is elevated using:

    su -

Main password hash is being held in .secret file.
SSH connection automatically accepts remote machines authentication keys.