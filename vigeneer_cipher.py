from plaintext import load_file

import re
import math
from collections import Counter
from functools import reduce

origin_text = load_file('plaintext.txt').upper()
key = "KEY"

'''
Створення шифру Віженера з відомим ключем
'''

# Функція розшинерення ключа до довжини тексту
def extend_key(text, key):
    key = list(key)
    # Якщо довжина ключа меньша за текст, циклічно повторюємо його 
    if len(text) == len(key):
        return key
    else:
        for i in range(len(text) - len(key)):
            key.append(key[i % len(key)])
        
    return ''.join(key)

# Функція шифрування за методом Віженера
def encrypt(text, key):
    # Розширюємо ключ
    key = extend_key(text, key)
    # Список для зашифрованого тексту
    encrypted_text = []

    for i in range(len(text)):
        x = ((ord(text[i]) - ord("A")) + (ord(key[i]) - ord('A'))) % 26
        x += ord('A')
        encrypted_text.append(chr(x))

    return ''.join(encrypted_text)

# Функція розшифрування шифру за методом Віженера
def decrypted(text, key):
    key = extend_key(text, key)
    origin_text = []

    for i in range(len(text)):
        x = ((ord(text[i]) - ord('A')) - (ord(key[i])  - ord('A')) + 26) % 26
        x += ord('A')
        origin_text.append(chr(x))

    return ''.join(origin_text)

encrypted_text = encrypt(origin_text, key)
print("Зашифрований текст:", encrypted_text)

decrypted_text = decrypted(encrypted_text, key)
print("Розшифрований текст:", decrypted_text)



'''
Дешифрування шифру Віженера без відомого ключа
'''



# Функція для пошуку повторюваних шаблонів
def find_repeating_patterns(text, n=3):
    # Створюємо регулярний вираз для пошуку n-літерних блоків
    pattern = r"(?=(\w{%d}))" % n
    matches = re.findall(pattern, text)
    return matches

# Функція для обчислення відстаней між однаковими шаблонами
def calculate_distances(matches):
    distances = {}
    
    # Створюємо словник, де ключем є шаблон, а значенням - список індексів
    for index, match in enumerate(matches):
        if match not in distances:
            distances[match] = []
        distances[match].append(index)
    
    # Обчислюємо відстані між кожною парою повторів шаблону
    distance_list = []
    for match, indices in distances.items():
        for i in range(1, len(indices)):
            distance_list.append(indices[i] - indices[i-1])
    
    return distance_list

# Функція для пошуку відстаней між повторюваними шаблонами
def find_key_length(crypted_text, n=3):
    # Пошук повторюваних шаблонів
    matches = find_repeating_patterns(crypted_text, n)
    
    # Обчислення відстаней 
    distances = calculate_distances(matches)
    
    # Підрахунок найпоширеніших відстаней (для визначення довжини ключа)
    counter = Counter(distances)
    most_common = counter.most_common(10)  
    print(f"Найбільш поширені відстані: {most_common}")
    
    return most_common

# Шифротекст
ciphertext = encrypted_text

# Викликаємо функцію для пошуку ймовірної довжини ключа
key_length_candidates = find_key_length(ciphertext, n=3)

# Частотність символів в англійській мові 
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ENGLISH_FREQ = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
    'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
    'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
    'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2,
    'Q': 0.1, 'Z': 0.1
}

# Функція розбиття шифротексту на стовпці (залежно від довжини ключа)
def split_text_by_key_length(text, key_length):
    columns = ['' for _ in range(key_length)]
    for i, char in enumerate(text):
        columns[i % key_length] += char
    return columns

# Функція для обчислення статистики хі-квадрат
def chi_squared_stat(column_text):
    column_len = len(column_text)
    if column_len == 0:
        return float('inf')

    observed_counts = Counter(column_text)
    expected_counts = {char: ENGLISH_FREQ.get(char, 0) / 100 * column_len for char in ALPHABET}

    chi_squared = sum(
        ((observed_counts.get(char, 0) - expected_counts[char]) ** 2) / expected_counts[char]
        for char in ALPHABET if expected_counts[char] > 0
    )
    return chi_squared

# Функція знаходження ключа методом частотного аналізу
def find_key(ciphertext, key_length):
    columns = split_text_by_key_length(ciphertext, key_length)
    key = ""

    for column in columns:
        best_shift = 0
        lowest_chi_squared = float('inf')

        for shift in range(26):
            decrypted_column = ''.join(
                ALPHABET[(ALPHABET.index(char) - shift) % 26] for char in column
            )
            chi_squared_value = chi_squared_stat(decrypted_column)

            if chi_squared_value < lowest_chi_squared:
                lowest_chi_squared = chi_squared_value
                best_shift = shift

        key += ALPHABET[best_shift]

    return key

def find_best_key_length(crypted_text, length_candidates):
    best_length = None
    best_chi_squared = float('inf')

    columns = split_text_by_key_length(crypted_text, length_candidates)
    chi_squared_sum = sum(chi_squared_stat(column) for column in columns)

    print(f"Перевіряємо довжину {length_candidates}: Хі-квадрат = {chi_squared_sum}")

    if chi_squared_sum < best_chi_squared:
        best_chi_squared = chi_squared_sum
        best_length = length_candidates

    return best_length

# Визначаємо можливі довжини ключа
first_numbers = [item[0] for item in key_length_candidates]

gcd_all = reduce(math.gcd, first_numbers)  
possible_lengths = gcd_all

# Функція дешифрування шифру Віженера
def decrypt_vigenere(ciphertext, key):
    decrypted_text = []
    key_length = len(key)

    for i, char in enumerate(ciphertext):
        shift = ALPHABET.index(key[i % key_length])
        decrypted_text.append(ALPHABET[(ALPHABET.index(char) - shift) % 26])

    return ''.join(decrypted_text)

# Шукаємо найкращий варіант
best_key_length = find_best_key_length(encrypted_text, possible_lengths)
print(f"Найімовірніша довжина ключа: {best_key_length}")

# Тепер знаходимо сам ключ
found_key = find_key(encrypted_text, best_key_length)
print(f"Знайдений ключ: {found_key}")

# Дешифруємо текст
decrypted_text = decrypt_vigenere(encrypted_text, found_key)
print(f"Розшифрований текст: {decrypted_text}")