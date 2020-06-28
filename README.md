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
echo 'abcdefgh' > file_with_passphrase
cat /path/to/file_with_passphrase | gpg2 --batch --passphrase-fd 0 --armor --decrypt /path/to/encrypted_file.pgp

gpg2 --batch --generate-key foo
gpg --list-secret-keys
gpg2 --armor --output public-key.gpg --export  joe@foo.bar
gpg --export-secret-keys -a joe@foo.bar --passphrase-fd 0 > private.key

cat file_with_passphrase | gpg2 --batch --passphrase-fd 0 --armor --decrypt private.key

cat file_with_passphrase | gpg2 --batch  --export-secret-keys -a joe@foo.bar --passphrase-fd 0 > private.key

cat file_with_passphrase | gpg --batch --export-secret-keys -a joe@foo.bar --passphrase-fd 0

gpg --pinentry-mode=loopback --passphrase  "abcdefgh" -d -o "private_key.jey" "PATH\TO\FILE.gpg"

gpg --batch --pinentry-mode=loopback --command-file file_with_passphrase --decrypt encrypted-file


gpg --batch --export-secret-keys -a joe@foo.bar --pinentry-mode=loopback --passphrase  "abcdefgh"