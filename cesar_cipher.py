from plaintext import load_file
from collections import Counter

origin_text = load_file('plaintext.txt').upper()

'''
Encrypt/Decrypt function by Cesar cipher
'''

def cesar_cipher(text: str, shift: int, mode: str = "encrypt") -> str:
    # Якшо mode = decrypt, зсув відбувається у зворотньому напрямку (дешифрування)
    if mode == "decrypt":
        shift = -shift
    
    # Змінна збереження результатів
    result = ''

    # Ітерація кожної літери в тексті. 
    for char in text:
        if char.isalpha():
            # Визначення стартової позиції
            start = ord('A') if char.isupper() else ord('a')

            # Застосування зсуву з mod 26
            new_char = chr(start + (ord(char) - start + shift) % 26)

        else:
            new_char = char

        result += new_char

    return result

# Шифруємо текст зі зсувом 3
encrypted_text = cesar_cipher(origin_text, 3, "encrypt")
print("Зашифрований текст:", encrypted_text)

# Дешифруємо назад
decrypted_text = cesar_cipher(encrypted_text, 3, "decrypt")
print("Розшифрований текст:", decrypted_text)

def cesar_decrypt_bruteforce(ciphertext: str) -> dict:

    # Підрахунок частоти появи букви в тексті
    letter_counts = Counter(filter(str.isalpha, ciphertext.upper()))

    if not letter_counts:
        return {"error": "У тексті немає літер!"}

    possible_decryption = {}

    # Перебір можливих зсувів
    for shift in range(26):
        decrypted_text = cesar_cipher(ciphertext, shift, "decrypt")
        possible_decryption[shift] = decrypted_text

    return possible_decryption

# Використання:
decryption_results = cesar_decrypt_bruteforce(encrypted_text)

# Виводимо всі варіанти розшифрування
for shift, text in decryption_results.items():
    print(f"Shift {shift}: {text}")