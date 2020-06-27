
#  projects/data-protection-01/locations/us/keyRings/test-key-ring-01/cryptoKeys/bucket-key-01/cryptoKeyVersions/1
from datetime import timedelta



def generatePGPKeys():
    import pgpy
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
    uid = pgpy.PGPUID.new('Abraham Lincoln', comment='Honest Abe',
                        email='abraham.lincoln@whitehouse.gov')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384,
                        HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                ciphers=[SymmetricKeyAlgorithm.AES256,
                        SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
                key_expires=timedelta(days=365))
    return key, key.pubkey


# [START kms_encrypt_symmetric]
def encrypt_symmetric(project_id, location_id, key_ring_id, key_id, private_key):
    """
    Encrypt plaintext using a symmetric key.

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        in_file (filename): file to encrypt
        out_file: encrypted_file

    Returns:
        bytes: Encrypted ciphertext.

    """

    # Import the client library.
    from google.cloud import kms

    # Import base64 for printing the ciphertext.
    import base64

    # Convert the plaintext to bytes.
    # plaintext_bytes = plaintext.encode('utf-8')
    plaintext_bytes = private_key.encode('utf-8')
    # in_file = open(in_file, "rb")  
    # plaintext_bytes = in_file.read()
    # in_file.close()

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the key name.
    key_name = client.crypto_key_path(
        project_id, location_id, key_ring_id, key_id)
    print(key_name)

    # Call the API.
   
    encrypt_pgpkey = client.encrypt(key_name, plaintext_bytes)
    # text_file = open(gcs_bucket, "wb")
    # n = text_file.write(encrypt_pgpkey.ciphertext)
    # text_file.close()
    return encrypt_pgpkey
# [END kms_encrypt_symmetric]


def upload_from_bytes(bucket_name, bytedata, destination_blob_name):
    from google.cloud import storage
    import io
    """Uploads a file to the bucket."""
    # bucket_name = "your-bucket-name"
    # source_file_name = "local/path/to/file"
    # destination_blob_name = "storage-object-name"

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    inMemTempFile = io.BytesIO(bytedata)
    blob.upload_from_file(inMemTempFile)


def upload_from_string(bucket_name, strData, destination_blob_name):
    from google.cloud import storage
    import io
    """Uploads a file to the bucket."""
    # bucket_name = "your-bucket-name"
    # source_file_name = "local/path/to/file"
    # destination_blob_name = "storage-object-name"

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    blob.upload_from_string(strData)

if __name__ == "__main__":
    pgpPrvKey, pgpPublicKey = generatePGPKeys()
    encrypt_pgpPrvKey = encrypt_symmetric('data-protection-01',
        'us', 'test-key-ring-01', 'bucket-key-01', str(pgpPrvKey))
    upload_from_string('test-bucket-01-01',
                encrypt_pgpPrvKey.ciphertext, 'private_key.key')
    upload_from_string('test-bucket-01-01',
                str(pgpPublicKey), 'public_key.txt')

