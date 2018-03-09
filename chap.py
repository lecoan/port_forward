import random
import hashlib
import json


def create_nonce(msg):
    return hashlib.sha224(msg.encode()).hexdigest()


class CHAP(object):
    def __init__(self, obj):
        self.id = 0
        self.local_storage = obj
        self.rand_dict = dict()

    def get_challenge(self, username):
        rand = str(random.randint(0, 9999)) + 'salt'
        self.id += 1
        data = {
            'code': 1,
            'id': self.id,
            'random': rand,
            'username': username
        }
        self.rand_dict[self.id] = rand
        string = json.dumps(data)
        return string

    def get_response(self, username, data):
        msg_id = data['id']
        rand = data['random']
        password = self.local_storage.get(data['username'])
        string = str(msg_id) + rand + password
        md5 = create_nonce(string)
        reply = {
            'code': 2,
            'id': msg_id,
            'hash': md5,
            'username': username
        }
        string = json.dumps(reply)
        return string

    def get_auth_result(self, data):
        msg_id = data['id']
        username = data['username']
        rand = self.rand_dict.get(msg_id)
        password = self.local_storage.get(username)
        string = str(msg_id) + rand + password
        md5 = create_nonce(string)

        hash_value = data['hash']
        reply = {'id': msg_id}
        if md5 == hash_value:
            reply['code'] = 3
            reply['message'] = 'authentication ok'
        else:
            reply['code'] = 4
            reply['message'] = 'authentication failed'
        string = json.dumps(reply)
        return string, md5 == hash_value
