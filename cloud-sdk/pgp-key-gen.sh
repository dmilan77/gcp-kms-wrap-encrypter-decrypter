#!/usr/bin/env bash
set +x
export GOOGLE_APPLICATION_CREDENTIALS="/app/gcp-sa.json"
gcloud auth activate-service-account --key-file=/app/gcp-sa.json
gcloud config set project  'data-protection-01'

expire_date='0'
key_length='2048'
key_type='RSA'
key_usage='encrypt,sign,auth'
name_comment='No comment'
name_email='milan.das77@gmail.com'
name_real='Milan Das'
passphrase="abcdef"
verbosity='--quiet'
kmsKeyring="test-key-ring-01"
kmsKey="bucket-key-01"
keyfile_name="milan-das"
bucketname="test-bucket-01-01"

# temp_dir=$(mktemp -d)

# Temporary file in memory
temp_dir=$(mktemp -d -p /dev/shm/)

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
echo "exporting public key ..."
gpg2  --batch --yes --no-tty --armor --export "$id"  > $temp_dir/${keyfile_name}-pubkey.txt
# export public key
echo "exporting private key ..."

#  export private key

echo "$passphrase" | gpg2  \
	--batch --yes --no-tty --pinentry-mode loopback --passphrase-fd 0 \
	--armor --export-secret-keys "$id" > $temp_dir/privatekey.key

gcloud kms encrypt \
    --key $kmsKey \
    --keyring $kmsKeyring \
    --location us  \
    --plaintext-file $temp_dir/privatekey.key \
    --ciphertext-file $temp_dir/${keyfile_name}-privatekey.key

gsutil cp $temp_dir/${keyfile_name}-privatekey.key  gs://${bucketname}/sshkeys/
gsutil cp $temp_dir/${keyfile_name}-pubkey.txt  gs://${bucketname}/sshkeys/