from asgiref.sync import async_to_sync
from channels.consumer import SyncConsumer
from channels.generic.websocket import WebsocketConsumer

from core.encryption_helpers import gpg_manager
from core.models import PGPKey

from django.conf import settings

import json, uuid


class InfoRelayConsumer(WebsocketConsumer):
    def connect(self):
        self.user = self.scope['user']
        self.session = self.scope['session']

        if self.user.is_authenticated:
            self.room_name = self.scope['url_route']['kwargs']['uuid']
            self.room_group_name = f"GPG_{self.room_name}"

            async_to_sync(self.channel_layer.group_add)(
                self.room_group_name,
                self.channel_name
            )

            self.accept()

            self.send(text_data=json.dumps({
                'message':{
                    'message_type':'application_response',
                    'message':'Connected to Websocket'
                    }
                })
            )
        else:
            self.reject()

    def disconnect(self, close_code):
        async_to_sync(self.channel_layer.group_discard)(
            self.room_group_name,
            self.channel_name
        )

    def event_handler(self, message_data):
        if 'action' in message_data:
            if message_data['action'] == 'CreateKey':
                self.send(text_data=json.dumps({'message':{
                    'message_type':'application_response',
                    'message':'Sending Command to GPG Wrapper'
                    }
                }))

                async_to_sync(self.channel_layer.send)(
                    'gpg-create-key',
                    {
                    'type':'create',
                    'uuid': message_data['uuid'],
                    'session': {
                        'key_data':self.session['key_data'],
                        'key_type':self.session['key_type']
                        }
                    }
                )

            elif message_data['action'] == 'EncryptDocument':
                async_to_sync(self.channel_layer.send)(
                    'gpg-document-handler',
                    {
                    'type':'encrypt',
                    'session': {
                        'websocket_uuid':self.session['websocket_uuid'],
                        'document_uuid':self.session['document_upload_id']
                        }
                    }
                )

                self.session['encrypt_command_sent'] = True
                self.session.save()
            elif message_data['action'] == 'DecryptDocument':
                async_to_sync(self.channel_layer.send)(
                    'gpg-document-handler',
                    {
                    'type':'decrypt',
                    'data': message_data['data'],
                    'websocket_uuid': self.room_name,
                    }
                )

            elif message_data['action'] == 'ReEncryptDocument':
                async_to_sync(self.channel_layer.send)(
                    'gpg-document-handler',
                    {
                    'type':'re_encrypt',
                    'data': message_data['data'],
                    'websocket_uuid': self.room_name,
                    }
                )


        if 'message_type' in message_data:
            if message_data['message_type'] == 'gnupg_log':
                self.send(text_data=json.dumps({
                    'message':{
                        'message_type':'debug_response',
                        'message':message_data['message']
                        }
                    })
                )

            elif message_data['message_type'] == 'application_response':
                self.send(text_data=json.dumps({'message':{
                    'message_type':'application_response',
                    'message':message_data['message']
                    }
                }))

            elif message_data['message_type'] == 'background_response':
                if 'status' in message_data:
                    if message_data['status'] in ['key_complete', 'key_complete_fingerprint']:
                        self.scope['session'].pop('key_data', None)
                        self.scope['session'].pop('key_type', None)
                        self.scope['session'].pop('websocket_uuid', None)
                        self.scope['session'].pop('proceed', None)
                        self.scope["session"].save()

                    if message_data['status'] == 'ENC_DONE':
                        self.scope['session'].pop('websocket_uuid', None)
                        self.scope['session'].pop('document_upload_id', None)
                        self.scope['session'].pop('encrypt_command_sent', None)
                        self.scope["session"].save()

                self.send(text_data=json.dumps({'message':{
                    'message_type':'background_response',
                    'status': message_data['status'],
                    'message':message_data['message']
                    }
                }))

            elif message_data['message_type'] == 'decryption_response':
                if message_data['status'] == 'OK':
                    self.scope['session']['file_download'] = message_data['message']
                    self.scope["session"].save()

                    self.send(text_data=json.dumps({'message':{
                        'message_type':'background_response',
                        'status': 'DEC_DONE',
                        }
                    }))
                else:
                    self.send(text_data=json.dumps({'message':{
                        'message_type':'background_response',
                        'status': message_data['status'],
                        'message':message_data['message']
                        }
                    }))                          


    def receive(self, text_data):
        try:
            message_data = json.loads(text_data)
        except JSONDecodeError as error:
            self.send(text_data=json.dumps({'message':{
                'type':'application_response',
                'message':'Invalid Message Received'
                }
            }))
        
        message = message_data['message']

        self.event_handler(message)
        
    def group_message(self, event):
        message = event['message']

        self.event_handler(message)


class GPGKeyConsumer(SyncConsumer):
    def create(self, message):
        async_to_sync(self.channel_layer.group_send)(
            f"GPG_{message['uuid']}",
            {
            'type':'group.message',
            'message':{
                'message_type':'application_response',
                'message':'Creating Key...'
                }
            }
        )

        if 'key_data' in message['session']:
            if 'key_type' in message['session']:
                key_manager = gpg_manager.KeyManager(message['uuid'])

                try:
                    name = message['session']['key_data']['realname']
                    email = message['session']['key_data']['email']
                    password = message['session']['key_data']['password']
                except KeyError:
                    async_to_sync(self.channel_layer.group_send)(
                        f"GPG_{message['uuid']}",
                        {
                        'type':'group.message',
                        'message':{
                            'message_type':'background_response',
                            'status':'key_failed',
                            'message':'Key Data Incomplete'
                            }
                        }
                    )

                if message['session']['key_type'] == 'MASTER':
                    key_fingerprint = key_manager.generate_master_keypair(name, email, password)

                    PGPKey.objects.filter(email=email).update(fingerprint=key_fingerprint)

                    async_to_sync(self.channel_layer.group_send)(
                        f"GPG_{message['uuid']}",
                        {
                        'type':'group.message',
                        'message':{
                            'message_type':'background_response',
                            'status':'key_complete_fingerprint',
                            'message': key_fingerprint
                            }
                        }
                    )

                elif message['session']['key_type'] == 'NORMAL':
                    key = key_manager.create_key(name, email, password)

                    PGPKey.objects.filter(email=email).update(fingerprint=key.fingerprint)

                    key = key_manager.export_key(key, password)

                    async_to_sync(self.channel_layer.group_send)(
                        f"GPG_{message['uuid']}",
                        {
                        'type':'group.message',
                        'message':{
                            'message_type':'background_response',
                            'status':'key_complete',
                            'message': key
                            }
                        }
                    )   

            else:
                async_to_sync(self.channel_layer.group_send)(
                    f"GPG_{message['uuid']}",
                    {
                    'type':'group.message',
                    'message':{
                        'message_type':'key_failed',
                        'message':'Key Type Data not Recieved'
                        }
                    }
                ) 
        else:
            async_to_sync(self.channel_layer.group_send)(
                f"GPG_{message['uuid']}",
                {
                'type':'group.message',
                'message':{
                    'message_type':'key_failed',
                    'message':'Key Data not Recieved'
                    }
                }
            )    

class GPGDocumentConsumer(SyncConsumer):
    def encrypt(self, message):
        websocket_uuid = message['session']['websocket_uuid']
        document_uuid = message['session']['document_uuid']

        async_to_sync(self.channel_layer.group_send)(
            f"GPG_{websocket_uuid}",
            {
            'type':'group.message',
            'message':{
                'message_type':'application_response',
                'message':'Encrypting Document...'
                }
            }
        )

        encryption_manager = gpg_manager.EncryptionManager(websocket_uuid)
        encrypt_status = encryption_manager.encrypt(document_uuid)

        if encrypt_status['status'] == 'OK':
            async_to_sync(self.channel_layer.group_send)(
                f"GPG_{websocket_uuid}",
                {
                'type':'group.message',
                'message':{
                    'message_type':'application_response',
                    'message':'Encryption Complete!'
                    }
                }
            )

            async_to_sync(self.channel_layer.group_send)(
                f"GPG_{websocket_uuid}",
                {
                'type':'group.message',
                'message':{
                    'message_type':'background_response',
                    'status':'ENC_DONE',
                    'message': 'Encryption Complete!'
                    }
                }
            )
        else:
            async_to_sync(self.channel_layer.group_send)(
                f"GPG_{websocket_uuid}",
                {
                'type':'group.message',
                'message':{
                    'message_type':'application_response',
                    'message':encrypt_status['message']
                    }
                }
            )

    def decrypt(self, message):
        encryption_manager = gpg_manager.EncryptionManager(message['websocket_uuid'])

        async_to_sync(self.channel_layer.group_send)(
            f"GPG_{message['websocket_uuid']}",
            {
            'type':'group.message',
            'message':{
                'message_type':'application_response',
                'message':'Decrypting Document...'
                }
            }
        )

        decrypted_data = encryption_manager.decrypt(message['data']['document_id'], "Pa2jL6MeRi234627893")
        if decrypted_data['status'] == 'OK':

            async_to_sync(self.channel_layer.group_send)(
                f"GPG_{message['websocket_uuid']}",
                {
                'type':'group.message',
                'message':{
                    'message_type':'decryption_response',
                    'status': 'OK',
                    'message':{
                        'file': decrypted_data['document'],
                        'document_id':message['data']['document_id']
                        }
                    }
                }
            )  

        else:
            async_to_sync(self.channel_layer.group_send)(
                f"GPG_{message['websocket_uuid']}",
                {
                'type':'group.message',
                'message':{
                    'message_type':'background_response',
                    'message':decrypted_data
                    }
                }
            )                  

    def re_encrypt(self, message):
        async_to_sync(self.channel_layer.group_send)(
            f"GPG_{message['websocket_uuid']}",
            {
            'type':'group.message',
            'message':{
                'message_type':'application_response',
                'message':'Starting Re-Encryption...'
                }
            }
        )

class SecureRemoveConsumer(SyncConsumer):
    def remove(self, message):
        file = message['file']

        encryption_manager = gpg_manager.EncryptionManager(str(uuid.uuid4()))
        encryption_manager.secure_remove(file)

        print(f'Securely Removed: {file}')