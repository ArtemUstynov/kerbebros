# This is a sample Python script.
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket
import ComHelper as ch
import json
from random import randbytes

HOST = 'localhost'
PORT = 6969

KNOWN_CLIENTS = {"tom": "t_pass", "mot": "m_pass"}
TGS_PASSWORDS = {"TGS1": "tg1_pass"}
INITIALIZED_PASSWORDS = {}


def launch(name):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        soc.bind((HOST, PORT))
        soc.listen()
        while True:
            con, addr = soc.accept()
            print(f"started kerbebros server at {addr}")
            process_message(con, addr)


def process_message(con: socket, addr: tuple):
    try:
        msg1 = json.loads(ch.receive_msg(con).decode())
        name = msg1["name"]
        if name in KNOWN_CLIENTS:
            tgs_k = randbytes(32).hex()
            print(tgs_k)
            msg2 = {"tgs_k": tgs_k}
            msg2_e = ch.encrypt_AES(INITIALIZED_PASSWORDS[name], json.dumps(msg2))
            ch.send_msg(con, msg2_e)

            msg3 = {"tgs_k": tgs_k, "client": name, "address": addr[0]}
            msg3_e = ch.encrypt_AES(INITIALIZED_PASSWORDS["TGS1"], json.dumps(msg3))
            ch.send_msg(con, msg3_e)
        else:
            print("fokoff", name)
        con.close()
    except Exception as e:
        con.close()
        print(e)
        # raise e


def init_passwords():
    for k, psswd in KNOWN_CLIENTS.items():
        INITIALIZED_PASSWORDS[k] = ch.create_key_from_passwd(psswd)
    for k, psswd in TGS_PASSWORDS.items():
        INITIALIZED_PASSWORDS[k] = ch.create_key_from_passwd(psswd)


if __name__ == '__main__':
    init_passwords()
    print("passwords ready")
    launch('PyCharm')
