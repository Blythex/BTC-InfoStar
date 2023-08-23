import secp256k1 as ice
from colorama import init, Fore, Back, Style
import hmac, struct, hashlib
from bit import Key
from mnemonic import Mnemonic
from pycoin.symbols.btc import network
from bip_utils import Bip39Languages, Bip39MnemonicDecoder, Bip39MnemonicValidator, Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip32Utils, Bip44Changes
import json
import random
import secrets
from tqdm import tqdm
import os
import shutil
from datetime import datetime
import io
import sys
import bit
import psutil
from enum import Enum
from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
with open('btc.bf', "rb") as fp:
    bloom_filterbtc = BloomFilter.load(fp)


# Globale Variable, um die Anzahl der gefundenen Adressen zu speichern
found_addresses_count = 0


def save_to_separate_file(data):
    # Convert all bytes objects in the data dictionary to hexadecimal strings
    for key, value in data.items():
        if isinstance(value, bytes):
            data[key] = value.hex()

    idx = 1
    filename = f"found_in_bloom_{idx}_" + data["compressed_address"] + ".json"
    
    # Überprüfen Sie, ob die Datei bereits existiert. Wenn ja, erhöhen Sie den Index und prüfen Sie erneut.
    while os.path.exists(filename):
        idx += 1
        filename = f"found_in_bloom_{idx}_" + data["compressed_address"] + ".json"
    
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)
    
    return filename

def save_option_9_data(data):
    idx = 1
    prefix = "option_9_special_"
    filename = f"{prefix}{idx}.json"
    
    while os.path.exists(filename):
        idx += 1
        filename = f"{prefix}{idx}.json"
    
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)
    
    return filename


MAX_PRIVATE_KEY = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Wähle was du möchstet aber blende alle anderen aus 

#MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
#MAX_FILE_SIZE = 250 * 1024 * 1024  # 250 MB
MAX_FILE_SIZE = 125 * 1024 * 1024  # 125 MB in Bytes

def save_to_file(data, prefix="data", extension="json"):
    """
    Saves data to a file. If file size exceeds MAX_FILE_SIZE, saves to a new file.
    """
    idx = 1
    filename = f"{prefix}_{idx}.{extension}"
    
    # Check if the file already exists. If yes, increment the index and check again.
    while os.path.exists(filename) and os.path.getsize(filename) + sys.getsizeof(data) > MAX_FILE_SIZE:
        idx += 1
        filename = f"{prefix}_{idx}.{extension}"
    
    with open(filename, "a") as file:
        json.dump(data, file, indent=4)
    
    return filename

def get_key_data(private_key_int, is_compressed_start):
    global found_addresses_count
    
    # Perform scalar multiplication to get the corresponding public key
    public_key_bytes = ice.scalar_multiplication(private_key_int)

    # The public_key_bytes already represents the uncompressed public key
    uncompressed_public_key_hex = public_key_bytes.hex()

    # Extract x and y coordinates from the public key
    x_coord = public_key_bytes[1:33].hex()
    y_coord = public_key_bytes[33:].hex()

    # Determine the prefix for the compressed public key based on the parity of y-coordinate
    prefix = "02" if int(y_coord, 16) % 2 == 0 else "03"
    compressed_public_key_hex = prefix + x_coord

    # Convert the private key to hexadecimal with leading zeros
    private_key_hex = format(private_key_int, '064x')

    # Convert the private key to WIF compressed format
    wif_compressed = ice.btc_pvk_to_wif(private_key_hex, is_compressed=True)

    # Convert the private key to WIF uncompressed format
    wif_uncompressed = ice.btc_pvk_to_wif(private_key_hex, is_compressed=False)

    # Generate different types of addresses based on whether the start key is compressed or uncompressed
    if is_compressed_start:
        compressed_address = ice.privatekey_to_address(0, True, private_key_int)
        uncompressed_address = None  # Uncompressed address is not generated for compressed public keys
        public_key_used = compressed_public_key_hex
    else:
        compressed_address = None  # Compressed address is not generated for uncompressed public keys
        uncompressed_address = ice.privatekey_to_address(0, False, private_key_int)
        public_key_used = uncompressed_public_key_hex


    # Generate different types of addresses
    compressed_address = ice.privatekey_to_address(0, True, private_key_int)
    uncompressed_address = ice.privatekey_to_address(0, False, private_key_int)
    p2sh_address = ice.privatekey_to_address(1, True, private_key_int)
    bech32_address = ice.privatekey_to_address(2, True, private_key_int)
    eth_address_pvk = ice.privatekey_to_ETH_address(private_key_int)

    # Calculate the Hash160 value for the public key
    hash160_value = ice.pubkey_to_h160(0, True, public_key_bytes)
    hash160_hex = hash160_value.hex()  # Convert the Hash160 byte value to hexadecimal string

    # Create the dictionary with the data
    data_dict = {
        "ethereum_address": eth_address_pvk,
        "private_key_int": private_key_int,
        "private_key_hex": "0x" + private_key_hex,
        "public_key_compressed": compressed_public_key_hex,
        "public_key_uncompressed": uncompressed_public_key_hex,
        "x_coord": x_coord,
        "y_coord": y_coord,
        "wif_compressed": wif_compressed,
        "wif_uncompressed": wif_uncompressed,
        "compressed_address": compressed_address,
        "uncompressed_address": uncompressed_address,
        "p2sh_address": p2sh_address,
        "bech32_address": bech32_address,
        "hash160": hash160_hex
    }

    # Überprüfen Sie die Existenz der Adresse im Bloom-Filter
    if compressed_address in bloom_filterbtc:
        # Wenn die Adresse im Bloom-Filter ist:
        # 1. Speichern Sie die Daten in einer separaten JSON-Datei
        filename = save_to_separate_file(data_dict)
        
        # 2. Geben Sie eine benutzerdefinierte Meldung in der Konsole aus
        print(f"Die Adresse {compressed_address} wurde im Bloom-Filter gefunden und in {filename} gespeichert!")
        
        # Erhöhen Sie den Zähler für gefundene Adressen
        found_addresses_count += 1

    return data_dict

def generate_sequential_keys(start=1, end=MAX_PRIVATE_KEY):
    for i in range(start, end + 1):
        yield i

def generate_random_key(start, end):
    if start > end:
        raise ValueError("Start value should be less than or equal to end value")
    return start + secrets.randbelow(end - start + 1)

def get_mnemonic_language():
    print("Wählen Sie eine Sprache für den Mnemonic:")
    print("1. Chinese_simplified")
    print("2. Chinese_traditional")
    print("3. Czech")
    print("4. English")
    print("5. French")
    print("6. Italian")
    print("7. Korean")
    print("8. Portuguese")
    print("9. Spanish")

    while True:
        choice = input()
        if choice.isdigit() and 1 <= int(choice) <= 9:
            return int(choice)
        else:
            print("Ungültige Eingabe. Bitte wählen Sie eine gültige Option (1-9):")


def hex_to_int(hex_value):
    """ Convert hexadecimal string to integer. """
    return int(hex_value, 16)

#########
def mnem_to_seed(words):
    salt = 'mnemonic'
    seed = hashlib.pbkdf2_hmac("sha512",words.encode("utf-8"), salt.encode("utf-8"), 2048)
    return seed


def bip39seed_to_bip32masternode(seed):
    h = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code

def parse_derivation_path(str_derivation_path="m/44'/0'/0'/0/0"):
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/0'/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(0x80000000 + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def parse_derivation_path2(str_derivation_path="m/49'/0'/0'/0/0"):      
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/49'/0'/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(0x80000000 + int(i[:-1]))
        else:
            path.append(int(i))
    return path
order	= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def derive_bip32childkey(parent_key, parent_chain_code, i):
    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & 0x80000000) != 0:
        key = b'\x00' + parent_key
    else:
        key = bit.Key.from_bytes(parent_key).public_key
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % order
        if a < order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)
    return key, chain_code
    
def bip39seed_to_private_key(bip39seed, n=1):
    const = "m/44'/0'/0'/0/"
    str_derivation_path = "m/44'/0'/0'/0/0"
    derivation_path = parse_derivation_path(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key
    
def bip39seed_to_private_key2(bip39seed, n=1):
    const = "m/49'/0'/0'/0/"
    str_derivation_path = "m/49'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key3(bip39seed, n=1):
    const = "m/84'/0'/0'/0/"
    str_derivation_path = "m/84'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key4(bip39seed, n=1):
    const = "m/44'/60'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/44'/60'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

strength = 128
mnemonic = Mnemonic('english')
words = mnemonic.generate(strength=strength)
###################################################################################################################################################################################################
class Bip39Languages(Enum):
    CHINESE_SIMPLIFIED = "chinese_simplified"
    CHINESE_TRADITIONAL = "chinese_traditional"
    CZECH = "czech"
    ENGLISH = "english"
    FRENCH = "french"
    ITALIAN = "italian"
    KOREAN = "korean"
    PORTUGUESE = "portuguese"
    SPANISH = "spanish"

def generate_random_mnemonics_and_keys(num_keys, num_words=12, language=Bip39Languages.ENGLISH):
    for _ in range(num_keys):
        # Generate mnemonic for the given strength
        mnemonic = Mnemonic(language.name.lower())
        words = mnemonic.generate(strength=num_words * 32 // 3)
        
        # Use the get_key_data_option_4 function to obtain the data for each derivation path
        data = get_key_data_option_4(int.from_bytes(mnem_to_seed(words), "big"), words)
        
        yield data
#######################################################################################################################################################################################
import random

def get_key_data_option_4(private_key: int, words: str) -> dict:
    global found_addresses_count

    # Ensure the private key is not larger than the maximum value for 32 bytes
    max_val_for_32_bytes = 2**256 - 1
    if private_key > max_val_for_32_bytes:
        private_key = max_val_for_32_bytes

    GROUP_ORDER_INT = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    if not (0 < private_key < GROUP_ORDER_INT):
        # Wenn private_key nicht im gültigen Bereich liegt, setzen Sie ihn auf einen zufälligen Wert im gültigen Bereich.
        private_key = random.randint(1, GROUP_ORDER_INT - 1)

    def get_individual_key_data(private_key: int, mnemonic: str, derivation_path: str) -> dict:
        max_val_for_32_bytes = 2**256 - 1
        if private_key > max_val_for_32_bytes:
            private_key = max_val_for_32_bytes
        pvk_bytes = private_key.to_bytes(32, byteorder="big")
        key = Key.from_bytes(pvk_bytes)
        public_key_bytes = ice.scalar_multiplication(private_key)
        public_key_hex = public_key_bytes.hex()
        wif_compressed = ice.btc_pvk_to_wif(format(private_key, '064x'), is_compressed=True)
        wif_uncompressed = ice.btc_pvk_to_wif(format(private_key, '064x'), is_compressed=False)
        compressed_address = ice.privatekey_to_address(0, True, private_key)
        uncompressed_address = ice.privatekey_to_address(0, False, private_key)
        x_coord = public_key_bytes[1:33].hex()
        y_coord = public_key_bytes[33:].hex()
        p2sh_address = ice.privatekey_to_address(1, True, private_key)
        bech32_address = ice.privatekey_to_address(2, True, private_key)
        eth_address_pvk = ice.privatekey_to_ETH_address(private_key)
        hash160_value = ice.pubkey_to_h160(0, True, public_key_bytes)
        hash160_hex = hash160_value.hex()
        
        data_dict = {
            "derivation_path": derivation_path,
            "mnemonic": mnemonic,
            "ethereum_address": eth_address_pvk,
            "private_key_int": private_key,
            "private_key_hex": "0x" + format(private_key, '064x'),
            "public_key": public_key_hex,
            "x_coord": x_coord,
            "y_coord": y_coord,
            "wif_compressed": wif_compressed,
            "wif_uncompressed": wif_uncompressed,
            "compressed_address": compressed_address,
            "uncompressed_address": uncompressed_address,
            "p2sh_address": p2sh_address,
            "bech32_address": bech32_address,
            "hash160": hash160_hex
        }

        # Bloom-Filter Überprüfung
        if compressed_address in bloom_filterbtc:
            # Speichern Sie die Daten in einer separaten JSON-Datei
            filename = save_to_file(data_dict)
            
            # Geben Sie eine benutzerdefinierte Meldung in der Konsole aus
            print(Fore.GREEN + f"Die Adresse {compressed_address} wurde im Bloom-Filter gefunden und in {filename} gespeichert!" + Fore.RESET)
            
            # Erhöhen Sie den Zähler für gefundene Adressen
            found_addresses_count += 1

        return data_dict

    seed = mnem_to_seed(words)
    pvk1 = bip39seed_to_private_key(seed)
    pvk2 = bip39seed_to_private_key2(seed)
    pvk3 = bip39seed_to_private_key3(seed)
    pvk4 = bip39seed_to_private_key4(seed)

    pvk1_int = int.from_bytes(pvk1, "big")
    pvk2_int = int.from_bytes(pvk2, "big")
    pvk3_int = int.from_bytes(pvk3, "big")
    pvk4_int = int.from_bytes(pvk4, "big")

    data1 = get_individual_key_data(pvk1_int, words, "m/44'/0'/0'/0/0")
    data2 = get_individual_key_data(pvk2_int, words, "m/49'/0'/0'/0/0")
    data3 = get_individual_key_data(pvk3_int, words, "m/84'/0'/0'/0/0")
    data4 = get_individual_key_data(pvk4_int, words, "m/44'/60'/0'/0/0")
    data5 = get_individual_key_data(private_key, words, "")
    
    # Save the combined data
    combined_data = {
        "data_pvk1": data1,
        "data_pvk2": data2,
        "data_pvk3": data3,
        "data_pvk4": data4,
        "data_pvk5": data5
    }
    save_to_file(combined_data, prefix="mnemonic_data")

    return combined_data


###################################################################################################################################################################################
def is_sorted_by_key(data_list, key):
    # Check if list is sorted by the given key
    return all(data_list[i][key] <= data_list[i+1][key] for i in range(len(data_list)-1))

def sort_and_save_data_by_key(data_list, key, file_name):
    # Sort data by the given key
    sorted_data = sorted(data_list, key=lambda x: x[key])

    # Save sorted data to a new file
    sorted_file_name = "sorted_" + key + "_" + file_name
    with open(sorted_file_name, "w", encoding="utf-8") as file:
        json.dump(sorted_data, file, indent=4, ensure_ascii=False)

    print(f"Data sorted and saved in {sorted_file_name}.")

def sort_data_by_wif(file_name):
    # Load data from file
    with open(file_name, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Check if data is already sorted by WIF
    if not is_sorted_by_key(data, 'wif_compressed'):
        print("Data is not sorted by WIF. Sorting now...")
        sort_and_save_data_by_key(data, 'wif_compressed', file_name)
    else:
        print("Data is already sorted by WIF.")


def sort_data_by_hex(file_name):
    # Load data from file
    with open(file_name, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Check if data is already sorted by hex
    if not is_sorted_by_key(data, 'private_key_hex'):
        print("Data is not sorted by hex. Sorting now...")
        sort_and_save_data_by_key(data, 'private_key_hex', file_name)
    else:
        print("Data is already sorted by hex.")

def sort_data_by_int(file_name):
    # Load data from file
    with open(file_name, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Check if data is already sorted by int
    if not is_sorted_by_key(data, 'private_key_int'):
        print("Data is not sorted by int. Sorting now...")
        sort_and_save_data_by_key(data, 'private_key_int', file_name)
    else:
        print("Data is already sorted by int.")

def sort_data_by_mnemonic(file_name):
    """ Sortiert Daten in einer Datei nach dem Mnemonic. """
    # Daten aus Datei laden
    with open(file_name, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Überprüfen, ob die Daten bereits nach Mnemonic sortiert sind
    if not is_sorted_by_key(data, 'mnemonic'):
        print("Daten sind nicht nach Mnemonic sortiert. Sortiere jetzt...")
        sort_and_save_data_by_key(data, 'mnemonic', file_name)
    else:
        print("Daten sind bereits nach Mnemonic sortiert.")

def generate_keys_based_on_public_range_sampled(start_pub_key, end_pub_key, num_samples):
    """Generiert private Schlüssel durch Sampling basierend auf einer Spanne von öffentlichen Schlüsseln."""
    for _ in range(num_samples):
        private_key_int = random.randint(1, MAX_PRIVATE_KEY)
        data = get_key_data(private_key_int)
        current_pub_key = data["public_key"]

        # Überprüfen Sie, ob der aktuelle öffentliche Schlüssel innerhalb des angegebenen Bereichs liegt
        if start_pub_key <= current_pub_key <= end_pub_key:
            yield data

def generate_keys_based_on_public_range_indefinitely(start_pub_key, end_pub_key, is_compressed_start):
    while True:
        # Generate a random private key
        private_key_int = random.randint(1, MAX_PRIVATE_KEY)
        data = get_key_data(private_key_int, is_compressed_start)
        
        if is_compressed_start:
            current_pub_key = data["public_key_compressed"]
        else:
            current_pub_key = data["public_key_uncompressed"]

        # Check if the current public key is within the specified range
        if int(start_pub_key, 16) <= int(current_pub_key, 16) <= int(end_pub_key, 16):
            yield data


def get_mnemonic_strength():
    print(Fore.YELLOW + "Choose the mnemonic strength:" + Fore.RESET)
    strengths = {
        12: 128,
        15: 160,
        18: 192,
        24: 256
    }
    for key in strengths.keys():
        print(Fore.BLUE + f"{key} words" + Fore.RESET)
    choice = int(input(Fore.WHITE + "Your choice (12, 15, 18, 24 or random): " + Fore.RESET))
    
    if choice == 'random':
        return random.choice(list(strengths.values()))
    return strengths.get(choice, 128)



def display_progress(matches_found, elapsed_time, generated_count):
    sys.stdout.write("\r")
    sys.stdout.write(f"Gefundene Adressen: {matches_found} | Verstrichene Zeit: {elapsed_time} | Adressen generiert und gespeichert: {generated_count}")
    sys.stdout.flush()
######################################################### MAIN ######################################################### MAIN #########################################################
 
def center_text_in_console(text):
    # Größe des Terminalfensters ermitteln
    columns, rows = shutil.get_terminal_size()

    # Text in Zeilen aufteilen
    text_lines = text.split("\n")

    # Jede Zeile zentrieren
    centered_text = "\n".join(line.center(columns) for line in text_lines)

    return centered_text

def display_menu():
    init()  # colorama initialisieren
    logo = """
                                          .:^^~7J?77J?J!77?J5555J7~~:.                              
                                      .^^?!!!..7J!:^~:!^~:~~Y7?7?YYGGYJ7!~:.                        
                                  .^~75~.:.    ~~.    .^   ^?...^!.^7JJJ?7JPJ!:                     
                               .^~J?::!.        .  :.      ..   .:.~  ^?YP!~JPYJ~.                  
                             .!5J~~   .            :      : ^.        :^7JJY?J7??J7^.               
                          .!?55^.!^                         .         ..^~JP!~7~^7!!!~.             
                         ~J5^GP^ ^:                              .:..     :7^!JJ~7YYP5Y^            
                      .~YJ7^.?G!                                 :^:^     ::. :PGP55P?^J?.          
                     .7Y7.  .YY^           .?JJJ!   ~???7^.     ..     .. .   !5YB?J?7!?YY.         
                     ?P^     !:            .&@@@P   P@@@&:      ::     :.     :~^?PY77JY?Y5.        
                    ~7^      7^            :&@@@5   G@@@#.                 ^.  ~!?!PJ7^7Y?JY        
                  .??:.      !.   .^^^::::.~&@@@5..:B@@@B                      ^.^?:5J?75J?G7       
                  ^P7:~      .    ?@@@&&&&&&@@@@&###@@@@&GP5J7~:              .^  !:~YYJ?Y!Y5^      
                  ?5:             Y@@@@@@@@@@@@@@@@@@@@@@@@@@@@#P7.                .75#GB!?PBY      
                 !JP.        ::   ^!!!75&@@@@@@@GYYYY5GB&@@@@@@@@@B^             .~.~7BPPGGPBP      
                .P~?.        ..         5@@@@@@@7      .:!G@@@@@@@@G             .! .~BYJPGYBG.     
                ^G.:                    5@@@@@@@!         .B@@@@@@@#.       7.       ^PJ7YGGGG:     
                ~J                      5@@@@@@@~         ~#@@@@@@@5       .Y.      .~#Y5P5PPB:     
                ~Y.                     5@@@@@@@!.::::^~75&@@@@@@&Y.        .       .?&Y55GYPG.     
                ~Y.                    .G@@@@@@@&&&&&&@@@@@@@@@&P!                  ^7&B55Y?BP.     
                7G.                    .#@@@@@@@@@@@@@@@@@@@@@@@&&BY^               ?!GYPJ?7G5      
               .JY:                    .#@@@@@@@7:^^^~!!J5G&@@@@@@@@&7              ..PGP5JYBJ      
               .Y5^                    .#@@@@@@@^          ^P@@@@@@@@&~             .:B#5PYY#5      
                7P^                    :#@@@@@@&^           :&@@@@@@@@?             77&&J75G&!      
                75:       .            :&@@@@@@&:           ?@@@@@@@@&~          !: ~Y&BY?55B!      
                7Y:      .~       .^^^^J@@@@@@@&^....::^~7YB@@@@@@@@@Y           :. :BG5PJ5BB^      
          .:    YB.               J@@&@@@@@@@@@@&####&&&@@@@@@@@@@@&J.              ~#Y?GJGPG!      
          ^J:  .PP.              :#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#G?:               7!#PP5PBG#7      
          :5!  7B7               :???JJJJJY&@@@#555#@@@@P55YJ?!^.                  77&BP?PGYB:  ^:  
          .75J.^Y?                        .#@@@5   P@@@#.                        ..^YBGY^JP55^?5J.  
           .:Y^.P!   ..                   :&@@@P   G@@@#.                       ~:!JG&577GYP5Y5~..  
             !J!Y7:  ..                   ^&@@@5   B@@@#.                       : .^PGGJYB55BJ^^7:  
         .~^ ^GJJG:  ::              ..   .~~~~:   ~!!7!                          ?YBPPJJGGBB!YG:   
          .!J~BGYP:  !^      :       ^~                                       .: :PJP#Y5?PY#P#5^.   
           ^!P&B?^.  ~!      :                       ~^                  :: . !~ .Y5#BYYYP5B@#~:.   
          ^~!Y@B??~ .::^      :.              :.     ..             ::   ^~:! ?^.~G?&5YJ5PPY&GJ~.   
    .^::^~75P#PBPBJ7Y..!  ..  :.   .:~!.~~    :.         .:.::  ..  ~:. .~. ~.^7^?55&BBPPJ#GB5J^  :.
    .^~YP??B##BGGPP5?^J^  .^     ^75J!: ::.^.^. .. ::  .~:::.!  ~7. ^:^ :7~:^.^5^5GG&##BB5PB@B7:75! 
   .. .!PYB#&YB#J7P5PJP7 :::^^.^?BJ!:~..5!~Y!5~.^.   .7..~^::?^~YJ~:Y.?^^YP!75PJ~GBB&&@&BG#&&#5P#?:~
   ??  ~^?#BBBJB!YP#B55GYP?~JJ~?@B5~^!?YBPYPJG~:^ :7!???J^?~7?JY55?!P?#?PBP5PP5PP&P5@&&####&&GPP5.7?
.~JB#55GBB#B#G!77^JBJ5GB&BY?#?5&5^~.75Y#&?#P^G5Y5^5PBBJY5PG!5P!7?5PJ5B#G#B#P!!5&&&5P@B#G#PG####GPJJ~
:!!!~YY5GG5!75JJ5~??::75PJ?PB 75?^7?YJ?~GGBJ7YYY~Y57?P!7PP5YP!^.JG7?G5JJY55Y??JPY??YG5P5G!JYJ555??7.
     ..~?J~:?5777~!J7 ~?Y77?J!^^~~:??YJ7?YJGG?5GY77YJ5PYJ777YJ!!!?PYJ5!:~7J5YY7Y7?!!777~~.  .:^:    
       ^:. .!^.:^:...:^:       ::..^^. :^?!~?7?YJ^:::^^!~J?!??J7?!!75J!:!^~:^^:..^^                 
                                    .^::.  ...   ..     .:    .::^^^^.  .   ^!:  ..                 
    """

    print(Fore.GREEN + center_text_in_console(logo) + Fore.RESET)
    
    # Hinzugefügte Leerzeilen
    print("\n\n\n")
    
    # Zusätzliche Tool-Informationen
    tool_info = """
                         (                     (                    
   (    *   )   (        )\ )       (          )\ )    )            
 ( )\ ` )  /(   )\      (()/(       )\ )      (()/( ( /(    )  (    
 )((_) ( )(_))(((_) ___  /(_)) (   (()/(   (   /(_)))\())( /(  )(   
((_)_ (_(_()) )\___|___|(_))   )\ ) /(_))  )\ (_)) (_))/ )(_))(()\  
 | _ )|_   _|((/ __|    |_ _| _(_/((_) _| ((_)/ __|| |_ ((_)_  ((_) 
 | _ \  | |   | (__      | | | ' \))|  _|/ _ \\__ \|  _|/ _` || '_| 
 |___/  |_|    \___|    |___||_||_| |_|  \___/|___/ \__|\__,_||_|   
                                                                   
Author : NixName420
https://github.com/NixName420/
Version : 1.0.5
Donation BTC : bc1qtkxuklcps9tf8hmgy8l62f5k8h3v2myduea68k
Donation ETH : 0x75c89c885CcddD181feaFA272351C87005CE7Afb
"""
    print(center_text_in_console(tool_info))
    
    print(Fore.RED + f"{len(bloom_filterbtc)} addresses have been loaded from btc.bf." + Fore.RESET)
    print(Fore.YELLOW + "Choose an option:" + Fore.RESET)
    options = [
        "Generate sequence of private keys",
        "Convert hexadecimal value to integer",
        "Generate random sequence of private keys",
        "Generate a mnemonic and private key in all four lengths (12, 15, 18, 24 words)",
        "Sort the data in the JSON file by hexadecimal value",
        "Sort the data in the JSON file by integer value",
        "Sort the data in the JSON file by WIF",
        "Sort the data in the JSON file by mnemonic",
        "Generate private keys based on a public key range"
    ]

    for i, option in enumerate(options, 1):
        print(Fore.BLUE + f"{i}. " + Fore.CYAN + option + Fore.RESET)

    choice = int(input(Fore.WHITE + "Your choice: " + Fore.RESET))
    return choice


def main():
    choice = display_menu()

    if choice == 1:
    
        def flush_to_file():
            nonlocal current_file_name
            with open(current_file_name, "a") as file:
                temp_content = temp_buffer.getvalue()
                file.write(temp_content)
                temp_buffer.seek(0)  # Reset the buffer for new content
                temp_buffer.truncate(0)

            # Check if file size exceeds MAX_FILE_SIZE
            if os.path.getsize(current_file_name) > MAX_FILE_SIZE:
                # Close current bracket for JSON
                with open(current_file_name, "a") as file:
                    file.write("\n]")

                # Start a new file
                nonlocal file_idx
                file_idx += 1
                current_file_name = f"sequential_key_data_{file_idx}.json"
                with open(current_file_name, "w") as file:
                    file.write("[\n")
        
        try:
            print(Fore.YELLOW + "Type 'back' to return to the main menu at any time." + Fore.RESET)
            
            start = input(Fore.BLUE + "Enter the starting value (default is 1): ")
            
            if start.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return

            start = int(start or 1)
            
            end = input(Fore.BLUE + f"Enter the ending value (default is {MAX_PRIVATE_KEY}): ")
            
            if end.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return

            end = int(end or MAX_PRIVATE_KEY)
            
            show_progress = input(Fore.BLUE + "Do you want to display the progress bar? (y/n): ").lower() == 'y'
            private_keys = generate_sequential_keys(start, end)

            file_idx = 1
            current_file_name = f"sequential_key_data_{file_idx}.json"
            temp_buffer = io.StringIO()  # Create a temporary buffer
            temp_buffer.write("[\n")

            generated_count = 0
            start_time = datetime.now()

            for pk in private_keys:
                generated_count += 1
                elapsed_time = datetime.now() - start_time
                data = get_key_data(pk, ice, bloom_filterbtc)
                data_str = json.dumps(data, indent=4)

                if generated_count != 1:  # Add comma for subsequent entries
                    temp_buffer.write(",\n")
                temp_buffer.write(data_str)

                # Regularly flush the content from the temp buffer to the file
                if generated_count % 100 == 0:  # Adjust this value as needed for more frequent saves
                    flush_to_file()

                if show_progress:
                    display_progress(found_addresses_count, elapsed_time, generated_count)

            # Close the final file after writing the last entry
            temp_buffer.write("\n]")
            flush_to_file()
            temp_buffer.close()
            print(Fore.CYAN + f"\nData has been saved in {current_file_name}.")

        except KeyboardInterrupt:
            # When the user interrupts the process
            print(Fore.RED + "\nUser interrupted the process.")
            # Save the data that has been generated up to this point
            flush_to_file()
            print(Fore.CYAN + f"\nData has been saved in {current_file_name}.")
            # Return to the main menu
            main()

    elif choice == 2:
        try:
            hex_value = input(Fore.BLUE + "Enter the hexadecimal value (or type 'back' to return to the main menu): ")
            
            if hex_value.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return

            int_value = hex_to_int(hex_value)
                
            max_int_value = 115792089237316195423570985008687907852837564279074904382605163141518161494337

            if int_value > max_int_value:
                print(Fore.RED + f"Error: The integer value {int_value} exceeds the maximum allowed value!")
            else:
                print(Fore.CYAN + f"The integer value of the hexadecimal {hex_value} is {int_value}")

        except KeyboardInterrupt:
            # Wenn der Benutzer den Prozess unterbricht
            print(Fore.RED + "\nUser interrupted the process.")
            # Zum Hauptmenü zurückkehren
            main()




    elif choice == 3:
        try:
            print(Fore.YELLOW + "Type 'back' to return to the main menu at any time." + Fore.RESET)
            
            start = input(Fore.BLUE + "Enter the starting value (default is 1): ")
            
            if start.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return

            start = int(start or 1)
            
            end = input(Fore.BLUE + f"Enter the ending value (default is {MAX_PRIVATE_KEY}): ")
            
            if end.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return
            
            end = int(end or MAX_PRIVATE_KEY)
            
            num_keys = end - start + 1
            show_progress = input(Fore.BLUE + "Do you want to display the progress bar? (y/n): ").lower() == 'y'

            file_idx = 1
            current_file_name = f"random_key_data_{file_idx}.json"
            temp_buffer = io.StringIO()  # Create a temporary buffer
            temp_buffer.write("[\n")

            def flush_to_file():
                nonlocal current_file_name

                with open(current_file_name, "a") as file:
                    temp_content = temp_buffer.getvalue()
                    file.write(temp_content)
                    temp_buffer.seek(0)  # Reset the buffer for new content
                    temp_buffer.truncate(0)

                # Check if file size exceeds MAX_FILE_SIZE
                if os.path.getsize(current_file_name) > MAX_FILE_SIZE:
                    # Close current bracket for JSON
                    with open(current_file_name, "a") as file:
                        file.write("\n]")

                    # Start a new file
                    nonlocal file_idx
                    file_idx += 1
                    current_file_name = f"random_key_data_{file_idx}.json"
                    with open(current_file_name, "w") as file:
                        file.write("[\n")

            generated_count = 0
            start_time = datetime.now()

            for i in range(num_keys):
                generated_count += 1
                elapsed_time = datetime.now() - start_time

                pk = generate_random_key(start, end)
                data = get_key_data(pk)
                data_str = json.dumps(data, indent=4)

                if generated_count != 1:  # Add comma for subsequent entries
                    temp_buffer.write(",\n")
                temp_buffer.write(data_str)

                # Regularly flush the content from the temp buffer to the file
                if generated_count % 100 == 0:  # Adjust this value as needed for more frequent saves
                    flush_to_file()

                if show_progress:
                    display_progress(found_addresses_count, elapsed_time, generated_count)

            # Close the final file after writing the last entry
            temp_buffer.write("\n]")
            flush_to_file()
            temp_buffer.close()
            print(Fore.CYAN + f"\nRandom key data has been saved in {current_file_name}.")

        except KeyboardInterrupt:
            # Wenn der Benutzer den Prozess unterbricht
            print(Fore.RED + "\nUser interrupted the process.")
            # Zum Hauptmenü zurückkehren
            main()

    elif choice == 4:
        try:
            print(Fore.YELLOW + "Type 'back' to return to the main menu at any time." + Fore.RESET)
            
            strength = get_mnemonic_strength()
            
            num_keys_input = input(Fore.BLUE + "Enter the number of mnemonics to generate: ")
            
            if num_keys_input.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return
            
            num_keys = int(num_keys_input)

            # Show progress bar for mnemonic generation
            show_progress_input = input(Fore.BLUE + "Do you want to display the progress bar? (y/n): ")
            
            if show_progress_input.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return
            
            show_progress = show_progress_input.lower() == 'y'

            # Start the timer
            start_time = datetime.now()

            # Initialize the list to store generated key data
            generated_key_data_list = []

            # Initialize the progress counter
            generated_count = 0

            for derived_keys in generate_random_mnemonics_and_keys(num_keys, strength // 32 * 3):
                for key_data in derived_keys:
                    generated_key_data_list.append(key_data)

                    # Increment the progress counter
                    generated_count += 1

                    # Save the generated key data
                    save_to_file(key_data, prefix="mnemonic_key_data")

                # Display progress if requested
                if show_progress:
                    elapsed_time = datetime.now() - start_time
                    display_progress(found_addresses_count, elapsed_time, generated_count)

            # Display completion message
            elapsed_time = datetime.now() - start_time
            print(Fore.CYAN + f"\nGenerated {generated_count} mnemonic key data entries in {elapsed_time}.")

        except KeyboardInterrupt:
            # Wenn der Benutzer den Prozess unterbricht
            print(Fore.RED + "\nUser interrupted the process.")
            # Zum Hauptmenü zurückkehren
            main()


    elif choice == 5:
        try:
            print(Fore.YELLOW + "Type 'back' to return to the main menu at any time." + Fore.RESET)
            
            file_name = input(Fore.BLUE + "Enter the name of the file to be sorted: ")
            
            if file_name.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return
            
            sort_data_by_hex(file_name)
            
        except KeyboardInterrupt:
            # Wenn der Benutzer den Prozess unterbricht
            print(Fore.RED + "\nUser interrupted the process.")
            # Zum Hauptmenü zurückkehren
            main()

    elif choice == 6:
        try:
            print(Fore.YELLOW + "Type 'back' to return to the main menu at any time." + Fore.RESET)
            
            file_name = input(Fore.BLUE + "Enter the name of the file to be sorted: ")
            
            if file_name.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return
            
            sort_data_by_int(file_name)
            
        except KeyboardInterrupt:
            # Wenn der Benutzer den Prozess unterbricht
            print(Fore.RED + "\nUser interrupted the process.")
            # Zum Hauptmenü zurückkehren
            main()

    elif choice == 7:
        try:
            print(Fore.YELLOW + "Type 'back' to return to the main menu at any time." + Fore.RESET)
            
            file_name = input(Fore.BLUE + "Enter the name of the file to be sorted: ")
            
            if file_name.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return
            
            sort_data_by_wif(file_name)
            
        except KeyboardInterrupt:
            # Wenn der Benutzer den Prozess unterbricht
            print(Fore.RED + "\nUser interrupted the process.")
            # Zum Hauptmenü zurückkehren
            main()

    elif choice == 8:
        try:
            print(Fore.YELLOW + "Type 'back' to return to the main menu at any time." + Fore.RESET)
            
            file_name = input(Fore.BLUE + "Enter the name of the file to be sorted: ")
            
            if file_name.lower() == 'back':
                print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                main()
                return
            
            sort_data_by_mnemonic(file_name)
            
        except KeyboardInterrupt:
            # Wenn der Benutzer den Prozess unterbricht
            print(Fore.RED + "\nUser interrupted the process.")
            # Zum Hauptmenü zurückkehren
            main()

    elif choice == 9:
    
        def flush_to_file():
            nonlocal current_file_name
            with open(current_file_name, "a") as file:
                temp_content = temp_buffer.getvalue()
                file.write(temp_content)
                temp_buffer.seek(0)  # Reset the buffer for new content
                temp_buffer.truncate(0)

            # Check if file size exceeds MAX_FILE_SIZE
            if os.path.getsize(current_file_name) > MAX_FILE_SIZE:
                # Close current bracket for JSON
                with open(current_file_name, "a") as file:
                    file.write("\n]")

                # Start a new file
                nonlocal file_idx
                file_idx += 1
                current_file_name = f"public_key_range_data_{file_idx}.json"
                with open(current_file_name, "w") as file:
                    file.write("[\n")

        try:
            print(Fore.YELLOW + "Note: Ensure that both the start and end public keys are either both compressed or both uncompressed." + Fore.RESET)
            print(Fore.YELLOW + "Compressed keys start with '02' or '03' and have a length of 66 characters. Uncompressed keys start with '04' and have a length of 130 characters." + Fore.RESET)
            print(Fore.YELLOW + "Type 'back' to return to the main menu at any time." + Fore.RESET)

            valid_start_prefixes = ["02", "03", "04"]
            valid_lengths = [66, 130]
            
            while True:
                start_pub_key = input(Fore.BLUE + "Enter the starting value of the public key: " + Fore.RESET)
                if start_pub_key.lower() == 'back':
                    print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                    main()
                    return
                
                end_pub_key = input(Fore.BLUE + "Enter the ending value of the public key: " + Fore.RESET)
                if end_pub_key.lower() == 'back':
                    print(Fore.YELLOW + "Returning to the main menu..." + Fore.RESET)
                    main()
                    return

                if (start_pub_key[:2] in valid_start_prefixes and len(start_pub_key) in valid_lengths) and (end_pub_key[:2] in valid_start_prefixes and len(end_pub_key) in valid_lengths):
                    break
                else:
                    print(Fore.RED + "Error: Invalid public key prefix or length. Ensure your public keys start with '02', '03', or '04' and have the correct length." + Fore.RESET)
                    continue
                
            is_compressed_start = len(start_pub_key) == 66
            is_compressed_end = len(end_pub_key) == 66
            
            if is_compressed_start != is_compressed_end:
                print(Fore.RED + "Error: Both the start and end values must either be both compressed or both uncompressed." + Fore.RESET)
                return
            
            show_progress = input(Fore.BLUE + "Do you want to display the progress bar? (y/n): ").lower() == 'y'
            keys_data = generate_keys_based_on_public_range_indefinitely(start_pub_key, end_pub_key, is_compressed_start)

            file_idx = 1
            current_file_name = f"public_key_range_data_{file_idx}.json"
            temp_buffer = io.StringIO()  # Create a temporary buffer
            temp_buffer.write("[\n")

            start_time = datetime.now()
            generated_count = 0
            for data in keys_data:
                generated_count += 1
                elapsed_time = datetime.now() - start_time
                data_str = json.dumps(data, indent=4)

                if generated_count != 1:
                    temp_buffer.write(",\n")
                temp_buffer.write(data_str)

                if temp_buffer.tell() > 5000:  # adjust for more frequent saves
                    flush_to_file()

                if show_progress:
                    display_progress(found_addresses_count, elapsed_time, generated_count)

            temp_buffer.write("\n]")
            flush_to_file()
            temp_buffer.close()
            print(Fore.CYAN + f"\nGenerated keys have been saved in '{current_file_name}'.")

        except KeyboardInterrupt:
            # When the user interrupts the process
            print(Fore.RED + "\nUser interrupted the process.")
            flush_to_file()
            print(Fore.CYAN + f"\nGenerated keys have been saved in '{current_file_name}'.")
            main()



    else:
        print("Ungültige Auswahl. Bitte wählen Sie eine der angegebenen Optionen. 1, 2, 3, 4, 5 oder 6)")

if __name__ == "__main__":
    main()
