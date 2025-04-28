import binascii


def bitwise_xor(a, b):
    """Perform XOR operation on two byte sequences of the same length."""
    return bytes(x ^ y for x, y in zip(a, b))


# Provided encrypted messages (hex-encoded)
encrypted_messages_hex = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

# Convert the hex-encoded ciphertexts into bytes
ciphertexts = [binascii.unhexlify(ct) for ct in encrypted_messages_hex]

# Extract the target encrypted message (the last one) and the others
target_encrypted = ciphertexts[-1]
ciphertexts = ciphertexts[:-1]

# Recover the key stream using multiple ciphertexts
key_stream = bytearray(len(target_encrypted))

for ct in ciphertexts:
    # XOR the target with each ciphertext
    xor_result = bitwise_xor(ct[:len(target_encrypted)], target_encrypted)

    # Infer key bytes assuming the original message has spaces (ASCII value 32)
    for i, byte in enumerate(xor_result):
        if 65 <= byte <= 90 or 97 <= byte <= 122:  # Check if the XOR result is a letter
            key_stream[i] = ct[i] ^ ord(' ')  # If the result is a letter, infer key byte

# Decrypt the target ciphertext using the inferred key stream
decrypted_target = bitwise_xor(target_encrypted, key_stream)

# Attempt to decode the decrypted message, replacing non-printable characters
decrypted_message = "".join(chr(b) if 32 <= b <= 126 else "_" for b in decrypted_target)

print("Decrypted Message:", decrypted_message)

# Recovering the key stream with a multiple-pass approach
key_stream_recovery = bytearray(len(target_encrypted))

# Try multiple ciphertext combinations to infer the key
for i in range(len(target_encrypted)):
    possible_key_bytes = []
    for ct in ciphertexts:
        for other_ct in ciphertexts:
            if ct != other_ct:
                # XOR two different ciphertexts
                xor_diff = bitwise_xor(ct[:len(target_encrypted)], other_ct[:len(target_encrypted)])

                # Check if the XOR result seems to form a printable character
                if 32 <= xor_diff[i] <= 126:
                    guessed_key_byte = ct[i] ^ ord(' ')  # Assuming space is in the original text
                    possible_key_bytes.append(guessed_key_byte)

    # Choose the most frequent key byte as the correct guess
    if possible_key_bytes:
        from collections import Counter

        key_stream_recovery[i] = Counter(possible_key_bytes).most_common(1)[0][0]

# Decrypt the target encrypted message using the inferred key stream
decrypted_target_recovered = bitwise_xor(target_encrypted, key_stream_recovery)

# Decode the message and replace non-printable characters with an underscore
recovered_message = "".join(chr(b) if 32 <= b <= 126 else '_' for b in decrypted_target_recovered)
print("Recovered Decrypted Message:", recovered_message)
