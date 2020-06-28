cat >foo <<EOF
     %echo Generating a basic OpenPGP key
     Key-Type: DSA
     Key-Length: 1024
     Subkey-Type: ELG-E
     Subkey-Length: 1024
     Name-Real: Joe Tester
     Name-Comment: with stupid passphrase
     Name-Email: joe@foo.bar
     Expire-Date: 0
     Passphrase: abc
     # Do a commit here, so that we can later print "done" :-)
     %commit
     %echo done
EOF
gpg --batch --generate-key foo
gpg --list-secret-keys
gpg --armor --output public-key.gpg --export  joe@foo.bar
gpg --export-secret-keys -a joe@foo.bar > private.key

---

cat >foo <<EOF
     %echo Generating a basic OpenPGP key
     Key-Type: DSA
     Key-Length: 2048
     Subkey-Type: ELG-E
     Subkey-Length: 2048
     Name-Real: Joe Tester
     Name-Comment: with stupid passphrase
     Name-Email: joe@foo.bar
     Expire-Date: 0
     Passphrase:  abcd123
     # Do a commit here, so that we can later print "done" :-)
     %commit
     %echo done
EOF
echo 'abcd123' > file_with_passphrase


gpg --batch --generate-key foo
gpg --list-secret-keys
gpg2 --armor --output public-key.gpg --export  joe@foo.bar
gpg --export-secret-keys -a joe@foo.bar --passphrase-fd 0 > private.key

cat file_with_passphrase | gpg2 --batch --passphrase-fd 0 --armor --decrypt private.key

cat file_with_passphrase | gpg2 --batch  --export-secret-keys -a joe@foo.bar --passphrase-fd 0 > private.key

cat file_with_passphrase | gpg --batch --export-secret-keys -a joe@foo.bar --passphrase-fd 0

gpg --pinentry-mode=loopback --passphrase  "abcdefgh" -d -o "private_key.jey" "PATH\TO\FILE.gpg"

gpg --batch --pinentry-mode=loopback --command-file file_with_passphrase --decrypt encrypted-file


gpg --batch --export-secret-keys -a joe@foo.bar --pinentry-mode=loopback --passphrase 'abcd123`


-----
expire_date='0'
key_length='3072'
key_type='RSA'
key_usage='encrypt,sign,auth'
name_comment=''
name_email='milan.das77@gmail.com'
name_real='Milan Das'
passphrase="abcdef"
verbosity='--quiet'

temp_dir=$(mktemp -d)
export GNUPGHOME="$temp_dir"
cat > "$temp_dir/.input" <<-EOF
	%echo Generating a basic GPG key
	Key-Type: $key_type
	Key-Length: $key_length
	Key-Usage: $key_usage
	Name-Real: $name_real
	${name_email:+"Name-Email: $name_email"}
	${name_comment:+"Name-Comment: $name_comment"}
	Expire-Date: $expire_date
	Passphrase: $passphrase
	%commit
EOF

gpg2  $verbosity --batch --no-tty --gen-key "$temp_dir/.input"
# Find key's ID.
id=$(gpg2 --no-tty --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec:/ { print $5 }')
echo "$id"
gpg2  --no-tty --list-keys

# export public key 
PUBKEY=$(gpg2  --batch --yes --no-tty --armor --export "$id")

# export public key

echo "$passphrase" | gpg2 $verbosity $(outfile_arg "$privkey_out") \
	--batch --yes --no-tty --pinentry-mode loopback --passphrase-fd 0 \
	--armor --export-secret-keys "$id"