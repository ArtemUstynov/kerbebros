# This is a sample Python script.
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket
import ComHelper as ch
import json
from random import randbytes

HOST = 'localhost'
PORT = 9696

SERVICE_PASSWORDS = {"file": "f_pass"}
TGS_PASSWORDS = {"TGS1": "tg1_pass"}
SERVICE_ALLOW_MAP = {"file": ['tom', 'mot']}
INITIALIZED_PASSWORDS = {}


def launch(name):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        soc.bind((HOST, PORT))
        soc.listen()
        while True:
            con, addr = soc.accept()
            print(f"started kerbebros tgs server at {addr}")
            process_message(con, addr)


def check_validity(service: str, as_msg3: dict, msg5: dict) -> bool:
    valid_service = service in SERVICE_ALLOW_MAP
    valid_client = as_msg3["client"] == msg5['client']
    allowed_user = msg5["client"] in SERVICE_ALLOW_MAP[service]
    return valid_client and valid_service and allowed_user


def respond(con: socket, service: str, name: str, addr: str, tgs_k: bytes):
    service_k = randbytes(32).hex()
    print(service_k)

    msg6 = {"fs_k": service_k, "client": name, "address": addr[0]}
    e_msg6 = ch.encrypt_AES(INITIALIZED_PASSWORDS["file"], json.dumps(msg6))
    ch.send_msg(con, e_msg6)

    msg7 = {"fs_k": service_k}
    e_msg7 = ch.encrypt_AES(tgs_k, json.dumps(msg7))
    ch.send_msg(con, e_msg7)


def process_message(con: socket, addr: tuple):
    try:
        msg4 = json.loads(ch.receive_msg(con).decode())
        msg5_e = ch.receive_msg(con)
        service = msg4['service']
        as_msg3_e = msg4['as_resp']
        as_msg3_e_j = json.loads(bytes.fromhex(as_msg3_e))
        as_msg3 = json.loads(
            ch.decrypt_AES(bytes.fromhex(as_msg3_e_j['nonce']), INITIALIZED_PASSWORDS['TGS1'],
                           bytes.fromhex(as_msg3_e_j['msg'])).decode())
        tgs_k = bytes.fromhex(as_msg3["tgs_k"])
        msg5_j = json.loads(msg5_e)
        msg5 = json.loads(ch.decrypt_AES(bytes.fromhex(msg5_j['nonce']), tgs_k, bytes.fromhex(msg5_j['msg'])).decode())
        if not check_validity(service, as_msg3, msg5):
            print("something is wrong")
            return
        respond(con, service, msg5['client'], addr[0], tgs_k)
        con.close()
    except Exception as e:
        con.close()
        print(e)
        # raise e


def init_passwords():
    for k, psswd in SERVICE_PASSWORDS.items():
        INITIALIZED_PASSWORDS[k] = ch.create_key_from_passwd(psswd)
    for k, psswd in TGS_PASSWORDS.items():
        INITIALIZED_PASSWORDS[k] = ch.create_key_from_passwd(psswd)


if __name__ == '__main__':
    init_passwords()
    print("passwords ready")
    launch('PyCharm')
