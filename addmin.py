#   version = 1.1.3
from conson import Conson
from getpass import getpass
import paramiko
import os
import sys
import time
import bcrypt
import threading
import secrets
import string
import platform


def clean(func):
    """
    Decorator containing window cleaning function.
    :param func: Passed function.
    :return:
    """

    def header():
        title = "### ADDMIN ###"
        print("{0}\n{1}\n{0}\n\n".format("#" * len(title), title))

    def fn(*args, **kwargs):
        system = os.name

        if system == "nt":
            os.system("cls")
        else:
            os.system("clear")
        header()
        return func(*args, **kwargs)

    return fn


def pc_data(param):
    if param == "nodename":
        if os.name == "nt":
            return platform.node()
        elif os.name == "posix":
            return os.uname().nodename


@clean
def loader(pwd_load=False, data_type=None):
    """
    Function responsible for importing files content, creating template files, checking password.
    :param pwd_load: False -> True if function is invoked for password management.
    :param data_type: None -> "hosts" or "users", to return proper dictionaries from inventory file.
    :return: False -> if files does not exist, String (password) or Dict(inventory).
    """

    def passgen(curr_pwd="", desired_length=12):
        """
        Password generator/extender.
        :param curr_pwd: String -> If password is defined but not long enough, it will be automatically extended.
        :param desired_length: Integer -> Desired length of password.
        :return: String -> New password.
        """
        charset = string.ascii_letters + string.digits + string.punctuation
        while len(curr_pwd) != desired_length:
            curr_pwd += secrets.choice(charset)
        return curr_pwd

    @clean
    def proceed(passwd):
        """
        Function responsible for checking password.
        :param passwd: True if .secret is present(password has been set) or False if password is meant to be set.
        :return: String -> password.
        """
        while True:
            input_pwd = getpass("Enter password: ")
            if len(input_pwd) == 0:
                print("Try again.")
                time.sleep(1)
            else:
                if passwd and bcrypt.checkpw(input_pwd.encode('UTF-8'), passwd.encode('UTF-8')):
                    return input_pwd
                elif passwd and not bcrypt.checkpw(input_pwd.encode('UTF-8'), passwd.encode('UTF-8')):
                    print("Incorrect password.")
                    ch = input("Try again? y/N: ")
                    if ch.lower() == "y":
                        continue
                    else:
                        sys.exit()
                else:
                    pwd_2 = getpass("Confirm new password: ")
                    if input_pwd == pwd_2:
                        with open(pwd_hash_file, "w") as pf:
                            hashed_password = bcrypt.hashpw(input_pwd.encode('UTF-8'), bcrypt.gensalt())
                            pf.write(hashed_password.decode('UTF-8'))
                        return input_pwd
                    else:
                        print("Password does not match.")
                        ch = input("Try again? y/N: ")
                        if ch.lower() == "y":
                            continue
                        else:
                            sys.exit(False)

    template = {"users": {"username": ["pubkey", "temp_pwd"]},
                "hosts": {"username@hostname/IP[:port]": "password"}}

    if not pwd_load:
        if os.path.exists(inventory_file_path):
            target = Conson(inventory_file_name, salt=password)
            target.load()
            if target() == template:
                return False
            if "users" in list(target()) and "hosts" in list(target()):
                if data_type is not None:
                    if data_type == "hosts":
                        for host, host_pwd in target()["hosts"].items():
                            if host_pwd.startswith("<") and host_pwd.endswith(">"):
                                temp_hosts = target()["hosts"]
                                temp_hosts[host] = target.unveil(target()["hosts"][host][1:-1])
                                target.create("hosts", temp_hosts)
                    elif data_type == "users":
                        temp_users = target()["users"]
                        change = False
                        changed_password = False
                        #   Check users data correctness
                        for user in list(temp_users):
                            if type(temp_users[user]) is not list:
                                temp_users[user] = [temp_users[user]]
                                change = True

                            if "ssh-rsa" in temp_users[user][0]:
                                temp_users[user].append("")
                            else:
                                temp_users[user].insert(0, "")
                                change = True

                            current_pwd = temp_users[user][1]
                            if len(current_pwd) < pwd_req_len:
                                change = True
                                changed_password = True
                                new_pwd = passgen(current_pwd, pwd_req_len)
                                temp_users[user][1] = new_pwd
                                print(f"Temporary password for {user} changed to\t{new_pwd}\n")

                            if current_pwd.startswith("<") and current_pwd.endswith(">"):
                                temp_users = target()["users"]
                                temp_users[user][1] = target.unveil(target()["users"][user][1][1:-1])
                                target.create("users", temp_users)

                        if change:
                            if changed_password:
                                print("\nKEEP THOSE PASSWORDS IN SAFE PLACE.")
                                input("Press ENTER to clear and continue...")
                            target.create("users", temp_users)
                            target.save()
                    return target()[data_type]
                else:
                    return target
            else:
                return False
        else:
            target = Conson(inventory_file_name, salt=password)
            for temp, temp_data in template.items():
                target.create(temp, temp_data)
            target.save()
            return False
    else:
        if os.path.exists(pwd_hash_file):
            with open(pwd_hash_file, "r") as f:
                return proceed(f.read())
        else:
            return proceed(False)


def pwd_encryption():
    """
    Checks if host(s) password(s) and temporary users passwords in inventory are encrypted. If not, encrypts them.
    :return:
    """
    changed = False
    users_changed = False
    target = loader()
    for host, pwd in target()["hosts"].items():
        if not pwd.startswith("<") and not pwd.endswith(">"):
            target.veil("hosts", host)
            temp_hosts = target()["hosts"]
            temp_hosts[host] = "<" + temp_hosts[host] + ">"
            target.create("hosts", temp_hosts)
            print(f"Administrator password for {host} has been encrypted.")
            changed = True

    # Creating separate temporary instance for conson.veil() application, due to nesting.
    temp_cred = Conson(salt=password)
    for username, cred in target()["users"].items():
        temp_cred.create(username, cred.copy())
        if not cred[1].startswith("<") and not cred[1].endswith(">"):
            users_changed = True
            temp_cred.veil(username, 1)
            temp_cred.create(username, [temp_cred()[username][0], "<" + temp_cred()[username][1] + ">"])
            print(f"Password for {username} has been encrypted.")

    if changed:
        if users_changed:
            print("\nEncrypted user credentials will overwrite raw passwords in inventory file:\n")
            for username, cred in target()["users"].items():
                print(f"{username}\t{cred[1]}")
            print("\nKEEP THOSE PASSWORDS IN SAFE PLACE.")
            input("Press ENTER to continue...")
            target.create("users", temp_cred())
        target.save()
        print("Inventory file updated successfully.")
        time.sleep(2)


def privkey_check(priv_path, pub_path):
    """
    Checking public-private key pair existence. Generates new pair if there is none; generates pubkey from privkey
     if not provided; checks correctness of key pair. Uses global password for encrypting both new and existing privkey.
    :param priv_path: String -> path to private key file.
    :param pub_path: String -> path to public key file.
    :return: String -> pubkey or None
    """
    global sysname

    if os.path.exists(priv_path):
        print("Private key file detected...")
        time.sleep(1)
        pubkey = None
        privkey = None
        try:
            #   try to load privkey(no-password attempt first)
            try:
                privkey = paramiko.RSAKey.from_private_key_file(filename=priv_path)
                pubkey = privkey.get_base64()
                privkey.write_private_key_file(filename=priv_path, password=password)
            except paramiko.ssh_exception.PasswordRequiredException:
                privkey = paramiko.RSAKey.from_private_key_file(filename=priv_path, password=password)
                pubkey = privkey.get_base64()
            except Exception as e:
                print(f"ERROR: Cannot read existing private key: {e}.")
                return False

                #   checking pubkey existence
            if os.path.exists(pub_path):
                print("Pubkey file detected...")
                time.sleep(1)
                with open(pub_path, "r") as f:
                    imported_pubkey = f.read().strip()
                if len(imported_pubkey) == 0 or "ssh-rsa" not in imported_pubkey.split():
                    raise Exception("Invalid pubkey format.")
                else:
                    if pubkey == imported_pubkey.split()[1]:
                        print("Private key check successful.")
                        time.sleep(1)
                        return imported_pubkey
                    else:
                        raise Exception("ERROR: public-private keys mismatch.")
            else:
                #      checking private key and re-generating public key
                try:
                    pubkey = privkey.get_base64()
                    full_pubkey = f"ssh-rsa {pubkey} addmin@{sysname}"
                    with open(pub_path, "w") as f:
                        f.write(full_pubkey)
                    print("Pubkey autogenerated from privkey...")
                    time.sleep(1)
                    return full_pubkey
                except Exception as err:
                    print(f"ERROR while generating public key: {err}")
        except Exception as err:
            print(f"ERROR: Invalid privkey: {err}")
            return False
    else:
        #   generating new pair
        key = paramiko.RSAKey.generate(3072)
        public_key = key.get_base64()
        key.write_private_key_file(priv_path, password=password)
        with open(pub_path, "w") as f:
            full_pubkey = f"ssh-rsa {public_key} addmin@{sysname}"
            f.write(full_pubkey)
        print("Public-private key pair has been created. Please, upload public key to target hosts.")
        return False


@clean
def execute():
    """
    Main function responsible for starting workers.
    :return:
    """

    def remote(remote_host, remote_pwd, users_pubkeys):
        """
        Each thread will start from here. this function contains all
        nested functions required for main purpose of program.
        :param remote_host: String -> username@[hostname or IP][:port], by default port is set to 22.
        :param remote_pwd: String -> sudo password required for obtaining elevated user privileges.
        :param users_pubkeys: Dictionary -> contains logins, public keys of users and temporary passwords.
        :return:
        """

        def shell_cmd(cmds):
            """
            Sub-function for remote shell commands execution function.
            :param cmds: String or List of shell commands to execute on remote host.
            :return: List -> stdin, stdout, stderr all together.
            """
            shell_output = []
            if type(cmds) is list:
                for cmd in cmds:
                    shell.send((cmd + "\n").encode('UTF-8'))
                    while not shell.recv_ready():
                        time.sleep(1)
                    shell_output.append(shell.recv(65535).decode("utf-8"))
            else:
                shell.send((cmds + "\n").encode('UTF-8'))
                while not shell.recv_ready():
                    time.sleep(1)
                shell_output = (shell.recv(65535).decode("utf-8").split())
            return shell_output

        def add_user(user_name, tmp_pwd):
            """
            Sub-function for adding user.
            :param user_name: String -> username.
            :param tmp_pwd: String -> temporary password from inventory file.
            :return:
            """
            #   because ssh password login will be blocked by default (only by pubkey authentication),
            #   this is only for elevating user privileges. User is forced to change on first login.
            commands = [f'useradd -m -s /bin/bash {user_name}',
                        f'echo "{tmp_pwd}\n{tmp_pwd}" | passwd {user_name}',
                        f'chage -d 0 {user_name}']
            output = shell_cmd(commands)
            pwd_success = False

            for item in output:
                if "hasło zostało zmienione" or "password updated succesfully" in item:
                    pwd_success = True
            if pwd_success:
                print(f"{rhost}: User {user} created successfully.")
            else:
                print(f"{rhost}: Failed to add user {user}.")

        def mod_sshd(user_name):
            """
            Sub-function modiying ssh server configuration file.
            :param user_name: String -> username.
            :return:
            """
            sshd_out = shell_cmd('cat /etc/ssh/sshd_config')
            #   Check if proper section exists in config file.
            if "AllowUsers" not in sshd_out:
                shell_cmd(f'echo "AllowUsers {user_name}" | tee -a /etc/ssh/sshd_config')
            else:
                #   Enable ssh login for user.
                if user_name not in sshd_out:
                    shell_cmd(f'sed -i "/^AllowUsers/s/$/ {user_name}/" /etc/ssh/sshd_config')
            # Performed by first invoke (addmin user).
            if user_name == ruser:
                sshd_params = ["PermitRootLogin", "PasswordAuthentication", "Protocol"]
                for param in sshd_params:
                    flag = 2 if param == sshd_params[2] else "no"
                    if param not in sshd_out:
                        shell_cmd(f'echo "{param} {flag}" | tee -a /etc/ssh/sshd_config')
                    else:
                        if sshd_out[sshd_out.index(param) + 1] == "#":
                            shell_cmd(f'echo "{param} {flag}" | tee -a /etc/ssh/sshd_config')
                        elif sshd_out[sshd_out.index(param) + 1] != flag:
                            shell_cmd(f"sed -i 's/^\s*\({param}\s*\).*$/\1{flag}/' /etc/ssh/sshd_config")

        def mod_authkeys(user_name, user_pubkey):
            """
            Sub-function modifying ssh server configuration file.
            :param user_name: String -> username.
            :param user_pubkey: String -> string with rsa public key.
            :return:
            """
            if len(user_pubkey) == 0 or "ssh-rsa" not in user_pubkey:
                print(f"WARNING: Missing ssh-rsa pubkey for {user_name}, skipping...")
                return
            try:
                #   Check if .ssh directory exists in the user's home directory.
                command = f'test -d /home/{user_name}/.ssh && echo "Exists" || echo "Not Exists"'
                ssh_dir_output = shell_cmd(command)
                ssh_dir_status = "{}{}".format("" if ssh_dir_output[-3] != "Not" else ssh_dir_output[-3] + " ",
                                               ssh_dir_output[-2])

                #   If .ssh directory does not exist, create it.
                if ssh_dir_status == 'Not Exists':
                    command = f'mkdir -p /home/{user_name}/.ssh'
                    shell_cmd(command)

                #   Check if authorized_keys file exists in the .ssh directory.
                command = f'test -f /home/{user_name}/.ssh/authorized_keys && echo "Exists" || echo "Not Exists"'
                authorized_keys_output = shell_cmd(command)
                authorized_keys_status = "{}{}".format("" if authorized_keys_output[-3] != "Not" else
                                                       authorized_keys_output[-3] + " ", authorized_keys_output[-2])

                #   If authorized_keys file does not exist, create it.
                msg_applied = f"{rhost}: Authorized keys setup completed for user {user_name}."

                if authorized_keys_status == 'Not Exists':
                    commands = [f'echo "{user_pubkey}" > /home/{user_name}/.ssh/authorized_keys',
                                f'chown -R {user_name}:{user_name} /home/{user_name}/.ssh']
                    shell_cmd(commands)
                    print(msg_applied)
                else:
                    #   If it exists, check if exact pubkey is already inside.
                    authkeys_output = shell_cmd(f'cat /home/{user_name}/.ssh/authorized_keys')
                    if user_pubkey.split()[1] not in authkeys_output:
                        shell_cmd(f'echo "{user_pubkey}" >> /home/{user_name}/.ssh/authorized_keys')
                        print(msg_applied)
                    else:
                        pure_key = user_pubkey.split()[1]
                        print(f"{rhost}: {user_name} key: {pure_key[:6]}...{pure_key[-6:]} already exists.")

                #   Change ownership of .ssh directory and authorized_keys file to user_name.
                command = f'sudo chown -R {user_name}:{user_name} /home/{user_name}/.ssh'
                shell_cmd(command)

            except Exception as err:
                print(f"{remote_host}: ERROR: {err}")

        def lock_user(user_name, unlock=False):
            """
            Subfunction for locking user access. Works whenever username in inventory starts with '#' (hashtag).
            Blocks logging in and ssh connections.
            :param user_name: String -> username.
            :param unlock:  Boolean -> since always executed, it will either attempt to lock(default) or unlock user.
            :return:
            """
            if unlock:
                print(f"{rhost}: Unlocking {user}...")
                flag = "-u"
                sshd = f'sed -i "/^AllowUsers/s/$/ {user_name}/" /etc/ssh/sshd_config'
            else:
                print(f"{rhost}: Locking out {user}...")
                flag = "-l"
                sshd = f'sed -i "/^AllowUsers/ s/\<{user_name}\>//g" /etc/ssh/sshd_config'
            commands = [
                f'passwd {flag} {user_name}',
                sshd
            ]
            shell_cmd(commands)

        def remove_user(user_name):
            """
            Subfunction to delete user completely from remote hosts. Requires '!' (exclamation mark) as
            first letter of username.
            :param user_name: String -> username.
            :return:
            """
            commands = [
                f'deluser --remove-home {user_name}',
                f'sed -i "/^AllowUsers/ s/\<{user_name}\>//g" /etc/ssh/sshd_config'
            ]
            shell_cmd(commands)

        def sudo_shell(supass):
            """
            Subfunction for invoking remote shell and elevating it to root.
            :param supass: String -> decrypted sudo password.
            :return: paramiko.Client().invoke_shell() with sudo privileges or None if invalid password.
            """
            negative_responses = [
                "Uwierzytelnienie się nie powiodło",
                "Authentication failure"
            ]
            supershell = client.invoke_shell()
            super_output = []
            while supershell.recv_ready():
                time.sleep(0.25)
            supershell.recv(65535)
            sudo_cmd = ["su -", supass, "whoami"]

            for cmd in sudo_cmd:
                supershell.send((cmd + "\n").encode("UTF-8"))
                while not supershell.recv_ready():
                    time.sleep(0.25)
                time.sleep(1)
                super_output = supershell.recv(65535).decode("UTF-8").splitlines() if cmd == sudo_cmd[2] else []

            if "root" not in super_output[-2] or any(failed in super_output for failed in negative_responses):
                return None
            else:
                return supershell

        ruser, rhost = remote_host.split(":")[0].split("@")
        rport = remote_host.split(":")[1] if len(remote_host.split(":")) == 2 else 22

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=rhost, port=rport, username=ruser, password=password, key_filename=privkey_file)

            shell = sudo_shell(remote_pwd)
            if shell is None:
                #   If sub-function fails to invoke elevated remote shell, close connection and raise error.
                client.close()
                raise Exception(f"Invalid sudo password")
            else:
                print(f"{rhost}: Elevated shell invoked.")

                # Acquire /etc/passwd content
                passwd_content = shell_cmd('cat /etc/passwd')

                mod_sshd(ruser)
                mod_authkeys(ruser, app_pubkey)

                #   Iterate over users from inventory and set flags if username contains ! or #.
                for user, pubkey_pwd in users_pubkeys.items():
                    remove_flag = False
                    lock_flag = False
                    if user.startswith("#"):
                        user = user[1:]
                        lock_flag = True
                    elif user.startswith("!"):
                        user = user[1:]
                        remove_flag = True

                    # Check if user is present in /etc/passwd
                    user_present = False
                    for content in passwd_content:
                        if user in content:
                            user_present = True
                    # If user is not marked for deletion, create his account.
                    if not user_present and not remove_flag:
                        print(f"{rhost}: {user} does not exist, creating...")
                        add_user(user, pubkey_pwd[1])
                        mod_sshd(user)
                        mod_authkeys(user, pubkey_pwd[0])
                        # Lock user if required.
                        if lock_flag:
                            lock_user(user)
                    else:
                        if lock_flag:
                            lock_user(user)
                        if remove_flag:
                            print(f"{rhost}: Removing {user}...")
                            remove_user(user)
                        else:
                            #   If user exists, try to update host configuration for this user.
                            print(f"{rhost}: {user} already exists, updating...")
                            mod_sshd(user)
                            mod_authkeys(user, pubkey_pwd[0])
                #   Attempt sshd service restart.
                try:
                    shell_cmd("systemctl restart sshd")
                    print(f"{rhost}: Performed sshd service restart.")
                except Exception as sr_error:
                    print(f"{remote_host}: Unable to restart sshd service: {sr_error}")
                print(f"{rhost}: Done.")
                client.close()

        except Exception as e:
            print(f"{remote_host}: ERROR: {e}")

    #   For each host introduced in inventory file, run concurrent thread.
    print("Establishing connections and acquiring superuser privileges...")
    for host, sudo_pwd in hosts.items():
        print(f"Running thread for {host}...")
        threading.Thread(target=remote, args=(host, sudo_pwd, users,)).start()


inventory_file_name = "inventory"
inventory_file_path = os.path.join(os.getcwd(), inventory_file_name)
pwd_hash_file = os.path.join(os.getcwd(), ".secret")
privkey_file = os.path.join(os.getcwd(), "privkey")
pubkey_file = os.path.join(os.getcwd(), "pubkey")
pwd_req_len = 12
sysname = pc_data("nodename")

password = loader(True)
users = loader(False, "users")
hosts = loader(False, "hosts")
app_pubkey = privkey_check(privkey_file, pubkey_file)

#   If any of required files was missing, tell user to update already crated templates and exit program.
if not users or not hosts or not password or not app_pubkey:
    print("Please update your inventory files.")
    input("Press ENTER to exit...")
    sys.exit()
else:
    #   Check if remote hosts passwords in inventory requires encryption.
    pwd_encryption()
    #   Run main function.
    execute()
