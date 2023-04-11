# This is a sample Python script.
import datetime
import json
from getpass import getpass
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket

import ComHelper as ch

SERVERS = {"AS": ('localhost', 6969), 'TGS': ('localhost', 9696), 'FS': ('localhost', 6699)}


def get_k_str(msg: dict, key: str, passwd: bytes) -> bytes:
    key_j = ch.decrypt_AES(bytes.fromhex(msg['nonce']), passwd, bytes.fromhex(msg['msg']))
    return bytes.fromhex(json.loads(key_j.decode())[key])


def talk_to_as(name: str) -> (bytes, bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVERS['AS'][0], SERVERS['AS'][1]))
        ch.send_msg(s, json.dumps({"name": name}).encode())
        msg2_e_j = ch.receive_msg(s)
        msg3_e_j = ch.receive_msg(s)
        return msg2_e_j, msg3_e_j


def talk_to_tgs(msg2_e_j: bytes, msg3_e_j: bytes, name: str, password: str, service_name: str) -> (bytes, bytes, bytes):
    msg2_e = json.loads(msg2_e_j)
    tgs_k = get_k_str(msg2_e, "tgs_k", ch.create_key_from_passwd(password))
    msg4 = json.dumps({"service": service_name, "as_resp": msg3_e_j.hex()}).encode("utf-8")
    msg5 = {"client": name, "timestamp": str(datetime.datetime.now())}
    msg5_e_j = ch.encrypt_AES(tgs_k, json.dumps(msg5))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVERS['TGS'][0], SERVERS['TGS'][1]))
        ch.send_msg(s, msg4)
        ch.send_msg(s, msg5_e_j)
        msg6_e_p = ch.receive_msg(s)
        msg7_e_p = ch.receive_msg(s)
        return msg6_e_p, msg7_e_p, tgs_k


def talk_to_fs(msg6_e_j: bytes, msg7_e_j: bytes, tgs_k: bytes, name: str):
    msg7_e = json.loads(msg7_e_j)
    fs_k = get_k_str(msg7_e, 'fs_k', tgs_k)
    msg8 = {"client": name, "timestamp": str(datetime.datetime.now())}
    msg8_e_j = ch.encrypt_AES(fs_k, json.dumps(msg8))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVERS['FS'][0], SERVERS['FS'][1]))
        ch.send_msg(s, msg6_e_j)
        ch.send_msg(s, msg8_e_j)
        response_e_j = json.loads(ch.receive_msg(s))
        response = ch.decrypt_AES(bytes.fromhex(response_e_j['nonce']), fs_k,
                                  bytes.fromhex(response_e_j['msg'])).decode()
        if "fokoff" == response:
            print("sorry, you have to fokoff")
        else:
            print("SUCCESS", response)


def connect_to_fs(name: str, password: str, service_name: str):
    msg2_e_j, msg3_e_j = talk_to_as(name)
    msg6_e_j, msg7_e_j, tgs_k = talk_to_tgs(msg2_e_j, msg3_e_j, name, password, service_name)
    talk_to_fs(msg6_e_j, msg7_e_j, tgs_k, name)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    connect_to_fs(input("name: "), input("password: "), input("service: "))
# connect_to_fs("tom", "t_pass", "file")
