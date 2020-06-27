
#  projects/data-protection-01/locations/us/keyRings/test-key-ring-01/cryptoKeys/bucket-key-01/cryptoKeyVersions/1

# [START kms_encrypt_symmetric]
def decrypt_symmetric(project_id, location_id, key_ring_id, key_id, in_file):
    """
    Decrypt the ciphertext using the symmetric key
    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        ciphertext (bytes): Encrypted bytes to decrypt.
    Returns:
        DecryptResponse: Response including plaintext.
    """

    # Import the client library.
    from google.cloud import kms
    import base64

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the key name.
    key_name = client.crypto_key_path(
        project_id, location_id, key_ring_id, key_id)
    in_file = open(in_file, "rb")
    ciphertext_bytes = in_file.read()
    in_file.close()
    decrypt_response = client.decrypt(key_name, ciphertext_bytes)
    text_file = open('keys/private_key_clear.txt', "wb")
    n = text_file.write(decrypt_response.plaintext)
    text_file.close()
    return str(decrypt_response.plaintext)

if __name__ == "__main__":
    prv_key=decrypt_symmetric('data-protection-01',
                      'us', 'test-key-ring-01', 'bucket-key-01', 'keys/private_key.key')
    print(prv_key)



