
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
    # text_file = open(out_file, "wb")
    # n = text_file.write(decrypt_response.plaintext)
    # text_file.close()
    return bytes(decrypt_response.plaintext)


def encrypt_file():
    import pgpy
    clear_message = pgpy.PGPMessage.new("testfile/cleartext.txt", file=True)
    pubkey, _ = pgpy.PGPKey.from_file('keys/public_key.txt')
    encrypted_message = pubkey.encrypt(clear_message)
    # print(encrypted_message.is_encrypted)
    encrypted_message_str = str(encrypted_message)
    with open("out/encrypted_cleartext.txt", "w") as text_file:
        print(f"{encrypted_message_str}", file=text_file)


def decrypt_file():
    import pgpy

    encrypted_file_obj = ''
    with open('out/encrypted_cleartext.txt', 'r') as readfile:
        encrypted_file_obj = readfile.read()
    encrypted_message = pgpy.PGPMessage.from_blob(bytes(encrypted_file_obj, encoding='utf-8'))
    private_key_bytes = decrypt_symmetric('data-protection-01',
        'us', 'test-key-ring-01', 'bucket-key-01', 'keys/private_key.key')
    private_key, _ = pgpy.PGPKey.from_blob(private_key_bytes)
    decrypted_message = private_key.decrypt(encrypted_message).message
    print(decrypted_message)

if __name__ == "__main__":
    encrypt_file()
    decrypt_file()

