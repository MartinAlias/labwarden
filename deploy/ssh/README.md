# Read-only SSH access for LabWarden

The `linux_ssh` collector logs in as a dedicated `labwarden` user. That user can
only run the fixed list of read-only commands in `labwarden-ssh-wrapper.sh`,
whatever the client asks for. Run the steps below on **each Linux host** you
want LabWarden to read, as root or with sudo.

## 1. Create a key pair (on the machine that runs LabWarden)

```sh
ssh-keygen -t ed25519 -f ~/.ssh/labwarden_ed25519 -C labwarden -N ""
```

Use one key for all hosts. It's useless without the forced command below.

## 2. Create the user and install the wrapper (on the target host)

```sh
sudo useradd --system --create-home --shell /bin/sh labwarden
sudo install -m 0755 -o root -g root labwarden-ssh-wrapper.sh /usr/local/bin/labwarden-ssh-wrapper
```

The wrapper is owned by root, so the `labwarden` user can't edit it.

## 3. Authorize the key with a forced command

Put this line, all on one line, in `/home/labwarden/.ssh/authorized_keys`.
Paste your real public key from `~/.ssh/labwarden_ed25519.pub`:

```
restrict,command="/usr/local/bin/labwarden-ssh-wrapper" ssh-ed25519 AAAA... labwarden
```

Then lock the file down:

```sh
sudo install -d -m 0700 -o labwarden -g labwarden /home/labwarden/.ssh
sudo chown labwarden:labwarden /home/labwarden/.ssh/authorized_keys
sudo chmod 0600 /home/labwarden/.ssh/authorized_keys
```

`restrict` turns off port forwarding, agent forwarding, X11 and the pty. `command=`
means any requested command, including an interactive shell, goes through the
wrapper.

## 4. Trust the host key (on the machine that runs LabWarden)

LabWarden never trusts unknown host keys. Connect once and check the fingerprint
against the one the host prints with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`:

```sh
ssh -i ~/.ssh/labwarden_ed25519 labwarden@HOST "ip -j route"
```

If you get JSON back, it works. `ssh labwarden@HOST "rm -rf /"` should print
`labwarden: command not allowed`.

## 5. Optional: nftables rules

Reading the firewall ruleset needs root. Allow exactly one command, with exactly
these arguments, using `sudo visudo -f /etc/sudoers.d/labwarden`:

```
labwarden ALL=(root) NOPASSWD: /usr/sbin/nft -j list ruleset
```

Check the path with `command -v nft`. Then set `nftables: true` in the target's options.

## 6. Configure LabWarden

```yaml
targets:
  - name: docker-server-host
    plugin: linux_ssh
    options:
      host: 192.168.20.10
      user: labwarden
      key_file: ~/.ssh/labwarden_ed25519
      nftables: true      # only after step 5
```

## Removing access

Delete the user with `sudo userdel -r labwarden`, then delete
`/usr/local/bin/labwarden-ssh-wrapper` and `/etc/sudoers.d/labwarden`.
