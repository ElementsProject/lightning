import string
import random


def generate_random_label():
    label_length = 8
    random_label = ''.join(random.choice(string.ascii_letters)
                           for _ in range(label_length))
    return random_label


def generate_random_number():
    return random.randint(1, 20_000_000_000_000_00_000)


def pay_with_thread(rpc, bolt11):
    try:
        rpc.pay(bolt11)
    except Exception as e:
        print(f"holdinvoice: Error paying payment hash:{e}")
        pass
