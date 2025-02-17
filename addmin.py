#   version = 1.2.9
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
import queue
import json


#   Flags:

verbose = any(flag in sys.argv[1:] for flag in ['-v', 'v', '--verbose'])
initiate = any(flag in sys.argv[1:] for flag in ['-i', 'i', '--init'])
skip_sshd_config = any(flag in sys.argv[1:] for flag in ['-s', 's', '--skip-sshd'])
o_b_o = any(flag in sys.argv[1:] for flag in ['-o', 'o', '--one-by-one'])
send_help = any(flag in sys.argv[1:] for flag in ['-h', 'h', '--help'])


def clean(func=None):
    """
    Decorator containing window cleaning function.
    :param func: Passed function.
    :return:
    """
    def swipe():
        system = os.name
        if system == "nt":
            os.system("cls")
        else:
            os.system("clear")

    def header():
        title = "### ADDMIN ###"
        print("{0}\n{1}\n{0}\n\n".format("#" * len(title), title))

    def fn(*args, **kwargs):
        swipe()
        header()
        return func(*args, **kwargs)

    global verbose

    if verbose:
        return func
    else:
        if func is not None:
            return fn
        else:
            swipe()


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
    if verbose:
        print("Loading data...")

    def passgen(curr_pwd="", desired_length=12):
        """
        Password generator/extender.
        :param curr_pwd: String -> If password is defined but not long enough, it will be automatically extended.
        :param desired_length: Integer -> Desired length of password.
        :return: String -> New password.
        """
        if verbose:
            print("{}password".format("Generating" if len(curr_pwd) == 0 else "Expanding"))

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
        if verbose:
            print("Proceed with password...")
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

    def key_or_file(phrase):
        """
        Check if pubkey postion in inventory is a proper pubkey or filename containing pubkey.
        :param phrase: String.
        :return: String or False if conditions not met.
        """
        def nothing():
            if verbose:
                print(f"Pubkey is absent...")
                return ""

        if verbose:
            print(f"Check pubkey presence...")
        try:
            if "ssh-rsa" in phrase.split():
                if verbose:
                    print(f"Detected public key sequence...")
                return phrase
            else:
                assumed_pubkey = os.path.join(users_pubkeys_dir, phrase)
                if os.path.exists(assumed_pubkey):
                    if verbose:
                        print(f"{phrase} file exists, trying to load...")
                    with open(assumed_pubkey, "r") as pkey_file:
                        public_key = pkey_file.read()
                    if len(public_key) == 0:
                        if verbose:
                            print(f"Pubkey file seems empty...")
                        nothing()
                    elif "ssh-rsa" in public_key.split():
                        if verbose:
                            print(f"Public key found...")
                        return public_key
                    else:
                        nothing()
                else:
                    nothing()
        except Exception:
            nothing()

    def checkout(inv_file_path):
        """
        Inventory file format verification.
        :param inv_file_path: String -> Path to inventory file.
        :return: Exception if conditions unmet, else True.
        """
        if verbose:
            print(f"Checking inventory file...")
        prefix = "Inventory: "
        with open(inv_file_path, "r") as inv_file:
            file_content = inv_file.read()
            if not file_content.startswith("{") and not file_content.endswith("}"):
                return Exception(f"{prefix}file does not contain jsonizable data.")
            else:
                file_content = json.loads(file_content)

        if len(file_content) != 2:
            return Exception(f"{prefix}file content is too short.")
        elif "users" not in file_content or "hosts" not in file_content:
            return Exception(f"{prefix}missing keys in inventory file.")
        elif len(file_content["users"]) == 0 or len(file_content["hosts"]) == 0:
            return Exception(f"{prefix}t least one user and one host must be provided.")
        elif file_content == template:
            return Exception(f"{prefix}file is a template.")
        else:
            if verbose:
                print(f"Inventory file OK")
            return True

    template = {
        "users": {
            "john_doe": ["pubkey", "temp_pwd"],
            "jane_doe": ["file.pub", "temp_pwd"]
        },
        "hosts": {
            "addmin@172.16.10.1:2137": "password",
            "master@domain.org": "password",
            "superuser@192.168.1.100": "password"
        }
    }

    try:
        if not pwd_load:
            if os.path.exists(inventory_file_path):
                verify = checkout(inventory_file_path)
                if type(verify) is Exception:
                    raise verify
                elif verify:
                    if verbose:
                        "Loading inventory as conson instance..."
                    target = Conson(inventory_file_name, salt=password)
                    target.load()

                    if not os.path.exists(users_pubkeys_dir):
                        if verbose:
                            "Creating missing 'users-pubkeys' directory..."
                        os.mkdir(users_pubkeys_dir)

                    if "users" in list(target()) and "hosts" in list(target()):
                        if data_type is not None:
                            if data_type == "hosts":
                                if verbose:
                                    print("Gathering hosts data...")
                                for host, host_pwd in target()["hosts"].items():
                                    if host_pwd.startswith("<") and host_pwd.endswith(">"):
                                        temp_hosts = target()["hosts"]
                                        temp_hosts[host] = target.unveil(target()["hosts"][host][1:-1])
                                        target.create("hosts", temp_hosts)
                            elif data_type == "users":
                                if verbose:
                                    print("Gathering users data...")
                                temp_users = target()["users"]
                                change = False
                                changed_password = False
                                pubkey_variation = {}

                                #   Check if inventory contains pubkey or pubkey file name and check its correctness
                                for user, user_pwd in temp_users.items():
                                    pubkey_variation[user] = key_or_file(user_pwd[0])

                                #   Check users data correctness
                                for user in list(temp_users):
                                    if type(temp_users[user]) is not list:
                                        temp_users[user] = [temp_users[user]]
                                        change = True

                                    if len(temp_users[user]) < 2:
                                        if "ssh-rsa" in pubkey_variation[user].split():
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

                                for user, user_pwd in temp_users.items():
                                    temp_users[user][0] = key_or_file(user_pwd[0])
                                target.create("users", temp_users)

                            return target()[data_type]
                        else:
                            return target
                    else:
                        return False
            else:
                if verbose:
                    print("Creating inventory template...")

                if not os.path.exists(users_pubkeys_dir):
                    if verbose:
                        "Creating missing 'users-pubkeys' directory..."
                    os.mkdir(users_pubkeys_dir)

                target = Conson(inventory_file_name, salt=password)
                for temp, temp_data in template.items():
                    target.create(temp, temp_data)
                target.save()
                return False
        else:
            if os.path.exists(pwd_hash_file):
                if verbose:
                    print("Obtaining main password secret...")
                with open(pwd_hash_file, "r") as f:
                    return proceed(f.read())
            else:
                return proceed(False)

    except Exception as loader_err:
        print(f"LOADER ERROR: {loader_err}")
        return False


def pwd_encryption():
    """
    Checks if host(s) password(s) and temporary users passwords in inventory are encrypted. If not, encrypts them.
    :return:
    """
    if verbose:
        print("Encrypting raw passwords...")
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
            changed = True
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
    if verbose:
        print("Checking public-private key pair presence...")
    global sysname

    if os.path.exists(priv_path):
        print("Private key file detected...")
        time.sleep(1)

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
    if verbose:
        print("MAIN FUNCTION STARTED")

    def remote(remote_host, remote_pwd, users_pubkeys, is_done):
        """
        Each thread will start from here. this function contains all
        nested functions required for main purpose of program.
        :param remote_host: String -> username@[hostname or IP][:port], by default port is set to 22.
        :param remote_pwd: String -> sudo password required for obtaining elevated user privileges.
        :param users_pubkeys: Dictionary -> contains logins, public keys of users and temporary passwords.
        :param is_done: Boolean -> indicates whether the thread finished successfully.
        :return:
        """

        def shell_cmd(cmds):
            """
            Sub-function for remote shell commands execution function.
            :param cmds: String or List of shell commands to execute on remote host.
            :return: List -> stdin, stdout, stderr all together.
            """
            if verbose:
                print(f"{rhost} REMOTE SHELL EXECUTION: {cmds}")
            shell_output = []
            if type(cmds) is list:
                for cmd in cmds:
                    if verbose:
                        print(f"\tCommand: {cmd}")
                    shell.send((cmd + "\n").encode('UTF-8'))
                    while not shell.recv_ready():
                        time.sleep(1)
                    response = shell.recv(65535).decode("utf-8")
                    shell_output.append(response)
                    if verbose:
                        print(f"\tResponse:\n{response}\n")
            else:
                shell.send((cmds + "\n").encode('UTF-8'))
                if verbose:
                    print(f"\tCommand: {cmds}")
                while not shell.recv_ready():
                    time.sleep(1)
                shell_output = shell.recv(65535).decode("utf-8").split()
                if verbose:
                    print(f"\tResponse:\n{shell_output}\n")
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
                        f'chage -d 0 {user_name}',
                        f'usermod -aG sudo {user_name}']
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
            Sub-function modifying ssh server configuration file.
            :param user_name: String -> username.
            :return:
            """

            sshd_params = {
                "Protocol": 2,
                "PasswordAuthentication": "no",
                "PermitRootLogin": "no",
                "AllowUsers": f"{user_name}"
            }
            conf_dir = "/etc/ssh/sshd_config.d/"
            conf_name = remote_host.split("@")[0] + ".conf"
            sshd_out_ls = shell_cmd(f'test -f {conf_dir}{conf_name} && echo "Exists" || echo "NotExists"')
            sshd_exists = "Exists" in sshd_out_ls
            cfg = {}

            if verbose:
                print(f"Looking for {conf_name}...", "FOUND" if sshd_exists else "NOT FOUND")

            if "NotExists" in sshd_out_ls:
                # Create new sshd config file
                for key, value in sshd_params.items():
                    sshd_cmd = f"echo '{key} {value}' >> {conf_dir}{conf_name}"
                    if verbose:
                        print(f"RUNNING: {sshd_cmd}")
                    shell_cmd(sshd_cmd)
                if verbose:
                    print(f"{conf_name} created: {sshd_params}")
            else:
                # Read current configuration and save it to dictionary
                for key, value in sshd_params.items():
                    if key in sshd_params.keys():
                        if key != "AllowUsers":
                            cfg[key] = shell_cmd(f'grep {key} {conf_dir}{conf_name}')[-2]
                            if verbose:
                                print(f"Key: {key} Current value: {cfg[key]}")
                        elif key == "AllowUsers":
                            cmd_result = shell_cmd(f'grep {key} {conf_dir}{conf_name}')[::-1]
                            cfg[key] = cmd_result[1:cmd_result.index("AllowUsers")]
                            if verbose:
                                print(f"Key: {key} Current value: {cfg[key]}")

                if user_name not in cfg["AllowUsers"]:
                    cfg["AllowUsers"].append(user_name)

                shell_cmd(f"rm {conf_dir}{conf_name}")
                for key, value in cfg.items():
                    if key != "AllowUsers":
                        sshd_cmd = f"echo '{key} {value}' >> {conf_dir}{conf_name}"
                        if verbose:
                            print(f"RUNNING: {sshd_cmd}")
                        shell_cmd(sshd_cmd)
                    elif key == "AllowUsers":
                        user_list = " ".join(value)
                        sshd_cmd = f"echo '{key} {user_list}' >> {conf_dir}{conf_name}"
                        if verbose:
                            print(f"RUNNING: {sshd_cmd}")
                        shell_cmd(sshd_cmd)

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

            def elevate(commands):
                super_output = []
                for cmd in commands:
                    if verbose:
                        print(f"\tCommand: {cmd}")

                    supershell.send((cmd + "\n").encode("UTF-8"))
                    while not supershell.recv_ready():
                        time.sleep(0.25)
                        if timeout <= 0:
                            return None
                    time.sleep(1)
                    super_output = supershell.recv(65535).decode("UTF-8").splitlines() if cmd == sudo_cmd[2] else []
                if verbose:
                    print(f"\tResponse: {super_output}")

                return super_output

            if verbose:
                print("Invoking elevated shell...")
            negative_responses = [
                "Uwierzytelnienie się nie powiodło",
                "Authentication failure"
            ]
            timeout = 5
            supershell = client.invoke_shell()

            while supershell.recv_ready():
                time.sleep(0.25)
                timeout -= 0.25
                if timeout <= 0:
                    return None
            supershell.recv(65535)
            su_cmd = ["su -", supass, "whoami"]
            sudo_cmd = ["sudo -i", supass, "whoami"]


            try:
                try_su = elevate(su_cmd)
                if "root" not in try_su[-2] or any(failed in try_su for failed in negative_responses):
                    if verbose:
                        print("'su' failed, trying 'sudo'...")
                    try_sudo = elevate(sudo_cmd)

                    if "root" not in try_sudo[-2] or any(failed in try_sudo for failed in negative_responses):
                        return None
                    else:
                        return supershell
                else:
                    return supershell
            except Exception as err:
                if verbose:
                    print(err)
                return None

        ruser, rhost = remote_host.split(":")[0].split("@")
        rport = remote_host.split(":")[1] if len(remote_host.split(":")) == 2 else 22

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=rhost, port=rport, username=ruser, password=remote_pwd,
                           passphrase=password, key_filename=privkey_file)

            attempt = 0
            while attempt < 3:
                attempt += 1
                shell = sudo_shell(remote_pwd)
                if shell is None:
                    if attempt < 3:
                        print(f"{rhost}: failed to invoke elevated shell... {attempt}/3")
                    else:
                        #   If sub-function fails to invoke elevated remote shell, close connection and raise error.
                        client.close()
                        raise Exception("Invalid sudo password")
                else:
                    print(f"{rhost}: Elevated shell invoked.")
                    break

            # Acquire /etc/passwd content
            passwd_content = shell_cmd('cat /etc/passwd')
            if not skip_sshd_config:
                mod_sshd(ruser)
            else:
                print("Skipping sshd_config modification...")
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
                    if not skip_sshd_config:
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
                        if not skip_sshd_config:
                            mod_sshd(user)
                        mod_authkeys(user, pubkey_pwd[0])
            #   Attempt sshd service restart.
            try:
                shell_cmd("systemctl restart sshd")
                print(f"{rhost}: Performed sshd service restart.")
            except Exception as sr_error:
                print(f"{remote_host}: Unable to restart sshd service: {sr_error}")
            print(f"{rhost}: Done.")
            is_done.put(True)
            client.close()

        except Exception as e:
            if str(e) == "Invalid sudo password":
                print(f"{remote_host}: ERROR: {e}")
                is_done.put(True)
            else:
                print(f"{remote_host}: ERROR: {e}")
                is_done.put(False)

    #   For each host introduced in inventory file, run concurrent thread.
    print("Establishing connections and acquiring superuser privileges...")
    if o_b_o:
        print("\nONE-BY-ONE MODE ACTIVE\n")
    results = {}
    threads = {}
    max_thread_try = 3

    for host in list(hosts):
        results[host] = [queue.Queue(), 0]

    for host in list(hosts):
        if host.startswith("#"):
            print(f"Skipping {host[1:]}:")
            hosts.pop(host)

    done = False
    while not done:
        done = True
        for host, sudo_pwd in hosts.items():
            result = False if results[host][0].empty() or results[host][1] == 0 else results[host][0].get_nowait()
            if results[host][1] == 0 or not result:
                results[host][1] += 1
                if results[host][1] <= max_thread_try:
                    print("{}unning thread for {}... {}/{}".format("R" if results[host][1] == 1 else "Re-r",
                                                                   host, results[host][1], max_thread_try))
                    threads[host] = threading.Thread(target=remote, args=(host, sudo_pwd, users, results[host][0]))
                    threads[host].start()
                    done = False
                    if o_b_o:
                        threads[host].join()
                else:
                    print(f"Job failed for {host}; check host configuration and inventory file.")
            elif result:
                results[host][0].put(True)

        if not o_b_o:
            for thread in list(threads.values()):
                thread.join()

    print("\n\nAll jobs done.")
    input("Press enter to exit...")
    clean()


def help_incoming():
    def get_format():
        if __file__.endswith(".py"):
            return "python3 addmin.py"
        elif __file__.endswith(".exe"):
            return "addmin.exe"
        else:
            return "addmin"
    i_am_helping = """
    {} [flag]
    
    Flags:
    -v, v, --verbose\t\tPrints as much (useful) data as it is possible.
    -i, i, --init\t\tCheck files only. Also, performs encryption on passwords in inventory file (if possible). 
    -s, s, --skip-sshd\t\tDo not modify sshd_config file on remote hosts.
    -o, o, --one-by-one\t\tRun operations(threads) on hosts one-by-one, not on all simultaneously.
    -h, h, --help\t\tShows this message.
    """.format(get_format())
    print(i_am_helping)


#   Global variables:
inventory_file_name = "inventory"
inventory_file_path = os.path.join(os.getcwd(), inventory_file_name)
pwd_hash_file = os.path.join(os.getcwd(), ".secret")
privkey_file = os.path.join(os.getcwd(), "addmin.priv")
pubkey_file = os.path.join(os.getcwd(), "addmin.pub")
users_pubkeys_dir = os.path.join(os.getcwd(), "users-pubkeys")
pwd_req_len = 12
sysname = pc_data("nodename")


if len(sys.argv) > 1 and not (verbose or initiate or skip_sshd_config or o_b_o or send_help):
    send_help = True

# This is self-explanatory...
if send_help:
    help_incoming()
    sys.exit()

#   Init section:
password = loader(True)
users = loader(False, "users")
hosts = loader(False, "hosts")
app_pubkey = privkey_check(privkey_file, pubkey_file)

#   If any of required files was missing, tell user to update already crated templates and exit program.
if not users or not hosts or not password or not app_pubkey:
    print("Please check/update your inventory files.")
    input("Press ENTER to exit...")
    clean()
    sys.exit()
else:
    #   Check if remote hosts passwords in inventory requires encryption.
    pwd_encryption()
    #   Run main function.
    if initiate:
        print("Initiation done.")
        input("Press ENTER to exit...")
        clean()
        sys.exit()
    else:
        if verbose:
            print("Initiation done.")
        execute()
