# This is a sample Python script.
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket
import ComHelper as ch
import json
from random import randbytes

HOST = 'localhost'
PORT = 6699

FS_PASSWORDS = {"file": "f_pass"}
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
        msg6_e_j = json.loads(ch.receive_msg(con).decode())
        msg6 = json.loads(
            ch.decrypt_AES(bytes.fromhex(msg6_e_j['nonce']), INITIALIZED_PASSWORDS['file'],
                           bytes.fromhex(msg6_e_j['msg'])).decode())

        fs_k = bytes.fromhex(msg6['fs_k'])

        msg8_e_j = json.loads(ch.receive_msg(con))
        msg8 = json.loads(ch.decrypt_AES(bytes.fromhex(msg8_e_j['nonce']), fs_k,
                                         bytes.fromhex(msg8_e_j['msg'])).decode())

        if msg6['client'] == msg8['client']:
            ch.send_msg(con, ch.encrypt_AES(fs_k, msg8['timestamp']))
        else:
            ch.send_msg(con, ch.encrypt_AES(fs_k, "fokoff"))
        con.close()

    except Exception as e:
        con.close()
        print(e)
        # raise e


def init_passwords():
    for k, psswd in FS_PASSWORDS.items():
        INITIALIZED_PASSWORDS[k] = ch.create_key_from_passwd(psswd)


if __name__ == '__main__':
    init_passwords()
    print("passwords ready")
    launch('PyCharm')
