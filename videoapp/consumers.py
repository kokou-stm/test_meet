# videoapp/consumers.py

import json
import base64
from channels.generic.websocket import AsyncWebsocketConsumer
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.conf import settings
from django.contrib.auth.models import User
from asgiref.sync import sync_to_async
from .models import *
from channels.db import  database_sync_to_async




class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        
        self.room_group_name = self.scope["url_route"]["kwargs"]["room_name"]
        print("Connexion établie",  self.room_group_name)
       
        meeting = await sync_to_async(Meeting.objects.get)(name = self.room_group_name)
        chat_message, created = await sync_to_async(Chatmessages.objects.get_or_create)(channel=meeting)
        #Chatmessages.objects.get_or_create(channel=meeting)
        
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
    
    async def receive(self, text_data):
        #print("receive, ", "=="*5, text_data)
        
        text_data_json = json.loads(text_data)
        #print("data: ", text_data_json)
        username = text_data_json.get('username')
        message = text_data_json.get('message')
        #numberOfDivs = text_data_json.get('numberOfDivs')
        #mesagechat, created = Messageschat.objects.get_or_create(identifiant=numberOfDivs, username=username, message= message)

        # Séparer la fonction de récupération ou création d'utilisateur
        user, created = await sync_to_async(User.objects.get_or_create)(username=username)
        meeting = await sync_to_async(Meeting.objects.get)(name = self.room_group_name)
        chat_message = await sync_to_async(Chatmessages.objects.get)(channel=meeting)
        
        if chat_message.messages_chat is None:
            chat_message.messages_chat = []
        if 'message' in text_data_json:
            
            message = text_data_json['message']
            
            chat_message.messages_chat.append({
                   'type': 'chat_message',
                    'message': message,
                    'username': username,
                })
            await sync_to_async(chat_message.save)()
            '''chat_message.messages_chat.append({
                   'type': 'chat_message',
                    'message': message,
                    'username': username,
                })
            chat_message.save()'''
            
           
        
            print("Message enregistré")
            print("Message reçu: ", message)
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message,
                    'username': username,
                   # 'numberOfDivs' :numberOfDivs
                }
            )
        elif 'file' in text_data_json:
            print("Receive: ", 'file')
            file_data = text_data_json['file']
            file_name = text_data_json['file_name']
            file_type = text_data_json['file_type']

            # Decode Base64 and save to file
            file_data = base64.b64decode(file_data)
            file_path = await sync_to_async(default_storage.save)(f"uploads/{file_name}", ContentFile(file_data))
            file_url = f"{settings.MEDIA_URL}{file_path}"
            
            # Create ChatFile instance if you have such a model
            # await sync_to_async(ChatFile.objects.create)(user=user, file=file_path)
            print("File url: ", file_url)  
            chat_message.messages_chat.append({
                    'type': 'chat_file',
                    'file_url': file_url,
                    'file_name': file_name,
                    'username': username
                })
            chat_message.save()
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_file',
                    'file_url': file_url,
                    'file_name': file_name,
                    'username': username
                }
            )

    async def chat_message(self, event):
        message = event['message']
        username = event['username']
        await self.send(text_data=json.dumps({
            'message': message,
            'username': username
        }))

    async def chat_file(self, event):
        file_url = event['file_url']
        file_name = event['file_name']
        username = event['username']
        await self.send(text_data=json.dumps({
            'file_url': file_url,
            'file_name': file_name,
            'username': username
        }))



class VoiceConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        print("Connection etablie voice")
        self.room_name = 'voice_room'
        await self.channel_layer.group_add(
            self.room_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_name,
            self.channel_name
        )

    async def receive(self, text_data):
        print("Message vocal reçu", text_data)
        text_data_json = json.loads(text_data)
        transcript = text_data_json.get('transcript')
        username = text_data_json.get('username')
        user, created = await sync_to_async(User.objects.get_or_create)(username=username)
        
        await self.channel_layer.group_send(
            self.room_name,
            {
                'type': 'voice_transcript',
                'transcript': transcript,
                'username': username,
            }
        )

    async def voice_transcript(self, event):
        transcript = event['transcript']
        username =  event['username']
        await self.send(text_data=json.dumps({
            'transcript': transcript,
           'username': username,
        }))


