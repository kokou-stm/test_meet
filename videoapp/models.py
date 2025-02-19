from django.db import models
from django.contrib.auth.models import User
import uuid


class VerificationCode(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='verification_code')
    code = models.CharField(max_length=6, unique=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def generate_code(self):
        self.code = str(uuid.uuid4().int)[:6]
        self.save()


class Meeting(models.Model):
    name = models.CharField(max_length=100)  # Nom du canal
    password = models.CharField(max_length=100)  # Mot de passe de la réunion
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création
    users = models.ManyToManyField(User, related_name='channels')
    host = models.ForeignKey(User, on_delete=models.CASCADE, related_name='hosted_meeting', null=True, blank=True) 
    def __str__(self):
        return self.name


class Rooms(models.Model):
    name = models.CharField(max_length=255, unique=True)  # Nom unique de la salle
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création
    host = models.ForeignKey(User, on_delete=models.CASCADE, related_name='hosted_rooms')  # L'hôte de la salle
    active = models.BooleanField(default=True)  
    channel = models.ForeignKey(Meeting, on_delete=models.CASCADE, related_name='room', null=True, blank=True) 
    users = models.ManyToManyField(User, related_name='rooms',   null=True, blank=True) 

    def __str__(self):
        return self.name


class ChatFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chat_files')  # Fichiers liés à un utilisateur
    file = models.FileField(upload_to='uploads/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"File by {self.user.username} at {self.created_at}"


class Messageschat(models.Model):
    identifiant = models.IntegerField(null= True, blank=True)
    text = models.CharField(max_length=255, null = True, blank=True)


class Chatmessages(models.Model):
    channel = models.ForeignKey(Meeting, on_delete=models.CASCADE)
    messages = models.JSONField(blank=True, null=True)
    messages_chat = models.JSONField(blank=True, null=True)
    
    def add_message(self, message):
        """Ajoute un message à l'historique JSON et limite à 50 messages max."""
        messages = self.messages
        messages.append(message)

        if len(messages) > 50:  # Limite le stockage à 50 messages
            messages.pop(0)

        self.messages = messages
        self.save()
