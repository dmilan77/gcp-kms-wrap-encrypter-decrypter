
#  projects/data-protection-01/locations/us/keyRings/test-key-ring-01/cryptoKeys/bucket-key-01/cryptoKeyVersions/1

# [START kms_encrypt_symmetric]
def encrypt_symmetric(project_id, location_id, key_ring_id, key_id, in_file, out_file):
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

    in_file = open(in_file, "rb")  
    plaintext_bytes = in_file.read()
    in_file.close()

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the key name.
    key_name = client.crypto_key_path(
        project_id, location_id, key_ring_id, key_id)
    print(key_name)

    # Call the API.
    encrypt_response = client.encrypt(key_name, plaintext_bytes)
    text_file = open(out_file, "wb")
    n = text_file.write(encrypt_response.ciphertext)
    text_file.close()
# [END kms_encrypt_symmetric]

if __name__ == "__main__":
    encrypt_symmetric('data-protection-01',
                          'us', 'test-key-ring-01', 'bucket-key-01', 'private.key', 'enc_private.key',)

