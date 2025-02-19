from django.shortcuts import render, redirect

# Create your views here.

#from .api import *
from django.shortcuts import render
from gtts import gTTS
import os, io, json
from io import BytesIO
import requests
#from openai import AzureOpenAI
from PIL import Image
#import langdetect
import shutil
from .api import *
from django.http import  JsonResponse
import time
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .agora.RtcTokenBuilder import RtcTokenBuilder, Role_Attendee
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.db.models import Q
from django.core.mail import EmailMessage
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse
from .models import *

from django.shortcuts import render, redirect

# Create your views here.

from .api import *
from django.shortcuts import render
from gtts import gTTS
import os, io, json
from io import BytesIO
import requests
#from openai import AzureOpenAI
from PIL import Image
#import langdetect
import shutil
from .api import *
from django.http import  JsonResponse
import time
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.db.models import Q
from django.core.mail import EmailMessage
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse
from .models import VerificationCode


from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.exceptions import ValidationError
import codecs,math
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, HttpResponseForbidden

# Create your views here.

@csrf_exempt
def generate_agora_token(request, channel_name):
    print("Channel:  ", channel_name)
    app_id = 'f2891190d713482dbed4c3fd804ec233'
    app_certificate = 'ec7803663ae640658b2a5afe5dc0894e'
    #channel_name = 'channel1'
    uid = 0  # Utilisez 0 pour des utilisateurs anonymes ou un UID spécifique
    #role = RtcTokenBuilder.Role_Attendee  # Utilisateur participant à la réunion
    expiration_time_in_seconds = 3600  # Durée de validité du token en secondes

    current_timestamp = int(time.time())
    privilege_expired_ts = current_timestamp + expiration_time_in_seconds

    token = RtcTokenBuilder.buildTokenWithUid(app_id, app_certificate, channel_name, uid, Role_Attendee, privilege_expired_ts)
    print("="*10, "token", "="*10)
    print(token, channel_name)
    print("="*10, "token", "="*10)
    return JsonResponse({'token': token})

@login_required
def index(request):
    return render(request, "index.html")



from django.shortcuts import render, redirect
from .models import Meeting
import random
import string



@csrf_exempt
def forgotpassword(request):
     if request.method =="POST":
          username = request.user.username
          email = request.POST.get("email")
          user = User.objects.filter(email= email).first()
          print("user", user )
          if user:
               print("User exist")
               token = default_token_generator.make_token(user)
               uid = urlsafe_base64_encode(force_bytes(user.id))
               current_host = request.META["HTTP_HOST"]
               Subject = "Password Reset VideoCall "
               
               code_message= f"""
                    <!DOCTYPE html>
                    <html lang="fr">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Code de Vérification</title>
                     <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">

                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                background-color: #f4f7fa;
                                color: #333;
                                margin: 0;
                                padding: 0;
                            }}
                            .container {{
                                max-width: 600px;
                                margin: 20px auto;
                                padding: 20px;
                                background-color: #ffffff;
                                border-radius: 8px;
                                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                            }}
                            h2 {{
                                color: #007bff;
                                text-align: center;
                            }}
                            p {{
                                font-size: 16px;
                                line-height: 1.6;
                                margin: 10px 0;
                            }}
                            .code{{
                                display: block;
                                font-size: 24px;
                                font-weight: bold;
                                color: #007bff;
                                text-align: center;
                                margin: 20px 0;
                                padding: 15px;
                                background-color: #f1faff;
                                border: 2px solid #007bff;
                                border-radius: 8px;
                            }}
                            .footer {{
                                text-align: center;
                                font-size: 14px;
                                margin-top: 20px;
                                color: #888;
                            }}
                            .button {{
                            display: inline-block;
                            padding: 12px 20px;
                            margin-top: 20px;
                            background-color: #007bff;
                            color: #fff;
                            text-decoration: none;
                            border-radius: 4px;
                            text-align: center;
                            font-size: 16px;
                            font-weight: bold;
                            border: 1px solid #007bff;
                        }}
                        .button:hover {{
                            background-color: #0056b3;
                            border-color: #0056b3;
                        }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h2>Hi {username},</h2>
                            <p>Are you having trouble signing in <strong>videoCall</strong>?

                            Resetting your password is easy.
                            Just click on the url below and follow the instructions.
                            We will have you up and running in no time.
                            </p>
                        
                              {current_host}/updatepassword/{token}/{uid}/
                         
                            <p>Note that this link is valid for 1 hour.

                             If you did not make this request then please ignore this email. 
               
                            </p>
                            <div class="footer">
                                <p>Thanks,
                                  VideoCall Authentication.</p>
                            </div>
                        </div>
                        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
                    </body>
                    </html>
                    """
               emailsender(Subject, code_message, user.email)
              
               
            
               #message = mark_safe(render_to_string("emailpsswdreset.html", {}))
               
               '''email = EmailMessage(Subject,
                             message,
                             f"VideoCall <{settings.EMAIL_HOST}>",
                             [user.email])

               email.send()'''
               messages.success(request, f"We have send a reset password email to {user.email}, open it and follow the instructions !",)
          else:
               print("User not exist")
               messages.error(request,"L'email ne correspond à aucun compte, veuillez vérifier et reessayer.")
     return render(request, "account/forgot_password.html")


@csrf_exempt
def updatepassword(request, token, uid):
    print(request.user.username, token, uid)
    try:
            user_id = urlsafe_base64_decode(uid)
            decode_uid = codecs.decode(user_id, "utf-8")
            user = User.objects.get(id= decode_uid)
                         
    except:
            return HttpResponseForbidden("You are not authorize to edit this page")
    print("Utilisateur: ", user)
    checktoken = default_token_generator.check_token( user, token)
    if not checktoken:
        return HttpResponseForbidden("You are not authorize to edit this page, your token is not valid or have expired")
    if request.method =="POST":
            user = User.objects.get(id= decode_uid)
            pass1= request.POST.get('pass1')
            pass2= request.POST.get('pass2')
            if pass1 == pass2:
                 try:
                        validate_password(pass1)
                        user.password = pass1
                        user.set_password(user.password)
                        user.save()
                        messages.success(request, "Your password is update sucessfully")
                 except ValidationError as e:
                      messages.error(request, str(e))
                      
                       
                 return redirect('login')
            else:
                 messages.eror(request, "Passwords not match")
        
    return render(request, "account/update_password.html")



@csrf_exempt
def register(request):
    mess = ""
    if request.method == "POST":
        
        print("="*5, "NEW REGISTRATION", "="*5)
        username = request.POST.get("username", None)
        email = request.POST.get("email", None)
        pass1 = request.POST.get("password1", None)
        pass2 = request.POST.get("password2", None)
        print(username, email, pass1, pass2)
        try:
            validate_email(email)
        except:
            mess = "Invalid Email"
        if pass1 != pass2 :
            mess += " Password not match"
        if User.objects.filter(Q(email= email)| Q(username=username)).first():
            mess += f" Exist user with email {email}"
        print("Message: ", mess)
        if mess=="":
            try:
                    validate_password(pass1)
                    user = User(username= username, email = email)
                    user.save()
                    user.password = pass1
                    user.set_password(user.password)
                    user.save()
                   

                    subject = "Bienvenue sur videoCall !"

                    email_message = f"""
                    <!DOCTYPE html>
                    <html lang="fr">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Bienvenue sur videoCall !</title>
                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                background-color: #f4f7fa;
                                color: #333;
                                margin: 0;
                                padding: 0;
                            }}
                            .container {{
                                max-width: 600px;
                                margin: 20px auto;
                                padding: 20px;
                                background-color: #ffffff;
                                border-radius: 8px;
                                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                            }}
                            h1 {{
                                color: #007bff;
                                text-align: center;
                            }}
                            p {{
                                font-size: 16px;
                                line-height: 1.6;
                                margin: 10px 0;
                            }}
                            ul {{
                                font-size: 16px;
                                margin: 10px 0;
                            }}
                            li {{
                                margin-bottom: 8px;
                            }}
                            .highlight {{
                                font-weight: bold;
                                color: #007bff;
                            }}
                            .footer {{
                                text-align: center;
                                font-size: 14px;
                                margin-top: 20px;
                                color: #888;
                            }}
                            .button {{
                                display: inline-block;
                                padding: 12px 20px;
                                margin-top: 20px;
                                background-color: #007bff;
                                color: #fff;
                                text-decoration: none;
                                border-radius: 4px;
                                text-align: center;
                            }}
                            .button:hover {{
                                background-color: #0056b3;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>Bienvenue sur videoCall, cher(e) {username} ! 🎉</h1>
                            <p>Nous sommes ravis de t’accueillir sur videoCall ! Ton compte a été créé avec succès, et tu es maintenant prêt(e) à explorer l'univers passionnant des appels vidéo multilingues.</p>
                            <p>Voici quelques fonctionnalités incroyables que tu peux découvrir dès maintenant :</p>
                            <ul>
                                <li><span class="highlight">Communique</span> avec des utilisateurs parlant différentes langues, avec ta voix instantanément traduite dans la langue de ton interlocuteur.</li>
                                <li><span class="highlight">Brise les barrières linguistiques</span> et échange facilement avec des personnes parlant français, anglais, espagnol, et bien d’autres !</li>
                                <li><span class="highlight">Profite d’une traduction fluide et en temps réel</span> grâce à notre technologie IA avancée.</li>
                                <li><span class="highlight">Explore une large sélection de langues</span> pour une expérience de communication véritablement mondiale.</li>
                            </ul>
                            <p>Nous sommes impatients de t’aider à connecter avec le monde entier de manière inédite.</p>
                            <p>Si tu as des questions ou besoin d’assistance, n’hésite pas à nous contacter à [ton adresse e-mail] ou à visiter notre page de support.</p>
                            <p>Encore une fois, bienvenue sur videoCall ! Nous sommes ravis de t’avoir parmi nous.</p>
                            <div class="footer">
                                <p>Cordialement,</p>
                                <p>L’équipe videoCall</p>
                                <a href="[Lien vers ton site]" class="button">Découvrir videoCall</a>
                            </div>
                        </div>
                    </body>
                    </html>

                    """
                    emailsender(subject, email_message, user.email)
                    '''email = EmailMessage(subject,
                             email_message,
                             f"VideoCall <{settings.EMAIL_HOST}>",
                             [user.email])

                    email.send()'''
                    mess = f"Welcome {user.username}, Your account is create successfully, to active your account, get you verification code in your email boss at {user.email}"
                        
                    messages.info(request, mess)

                    verification_code, created = VerificationCode.objects.get_or_create(user=user)
                    verification_code.generate_code()
                    print(verification_code.code)
                    code_subject = "Votre code d'activation videoCall !"
                    code_message= f"""
                    <!DOCTYPE html>
                    <html lang="fr">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Code de Vérification</title>
                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                background-color: #f4f7fa;
                                color: #333;
                                margin: 0;
                                padding: 0;
                            }}
                            .container {{
                                max-width: 600px;
                                margin: 20px auto;
                                padding: 20px;
                                background-color: #ffffff;
                                border-radius: 8px;
                                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                            }}
                            h2 {{
                                color: #007bff;
                                text-align: center;
                            }}
                            p {{
                                font-size: 16px;
                                line-height: 1.6;
                                margin: 10px 0;
                            }}
                            .code{{
                                display: block;
                                font-size: 24px;
                                font-weight: bold;
                                color: #007bff;
                                text-align: center;
                                margin: 20px 0;
                                padding: 15px;
                                background-color: #f1faff;
                                border: 2px solid #007bff;
                                border-radius: 8px;
                            }}
                            .footer {{
                                text-align: center;
                                font-size: 14px;
                                margin-top: 20px;
                                color: #888;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h2>Bonjour,</h2>
                            <p>Votre code de vérification pour activer votre compte sur <strong>videoCall</strong> est :</p>
                            <div class="code">{verification_code.code}</div>
                            <p>Merci de l'utiliser pour valider votre inscription.</p>
                            <div class="footer">
                                <p>Si vous avez des questions, n'hésitez pas à nous contacter.</p>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                    emailsender(code_subject, code_message, user.email)
                   
                    return redirect("code")
            except Exception as e:
                    print("error: ", e)
                    #err = " ".join(e)
                    messages.error(request, e)
                    return render(request, template_name="register.html")
            
        #messages.info(request, "Bonjour")

    return render(request, template_name="register.html")


def connection(request):
    mess = ""

    if request.method == "POST":
        print("="*5, "NEW CONNECTION", "="*5)
        email = request.POST.get("email")
        password = request.POST.get("password")
        remember_me = request.POST.get("remember_me")  # Récupération de l'option "Se souvenir de moi"
        
        try:
            validate_email(email)
        except:
            mess = "Invalid Email !!!"

        if mess == "":
            user = User.objects.filter(email=email).first()
            if user:
                auth_user = authenticate(username=user.username, password=password)
                if auth_user:
                    print("Utilisateur infos: ", auth_user.username, auth_user.email)
                    
                    # Authentification et gestion de session
                    login(request, auth_user)
                    
                    # Gérer la durée de la session
                    if remember_me:  # Si "Se souvenir de moi" est coché
                        request.session.set_expiry(settings.SESSION_COOKIE_AGE)  # 30 jours
                    else:
                        request.session.set_expiry(0)  # Expire à la fermeture du navigateur
                    
                    return redirect("index")
                else:
                    mess = "Incorrect password"
            else:
                mess = "User does not exist"
            
        messages.info(request, mess)

    return render(request, template_name="login.html")


def code(request):
    mess = ""

   
    if request.method == "POST":
        
        print("="*5, "NEW CONECTION", "="*5)
        email = request.POST.get("email")
        code_v = request.POST.get("code")
        user = User.objects.filter(email= email).first()
        verification_code, created = VerificationCode.objects.get_or_create(user=user)
        
        print(verification_code.code)
        if str(code_v) == str(verification_code.code) :
            messages.info(request, "Code valide")
            return redirect("login")
        else:
            mess = "Invalid code !!!"
      
        messages.info(request, mess)

    return render(request, template_name="code.html")



def deconnexion(request):
         print("Deconnexion")
         logout(request)
         return redirect("index")
    

def create_meeting(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        password = request.POST.get('password')
        # Créer une réunion avec le nom et mot de passe fournis
        meeting = Meeting.objects.create(name=name, password=password, host=request.user )
        meeting.users.add(request.user)
        meeting.save()
        return redirect('home', meeting_id=meeting.id)
        #return redirect('join_meeting', meeting_id=meeting.id)
    return render(request, 'create_meeting.html')


@login_required
def home(request, meeting_id=None):
    
    if meeting_id:
        meeting = Meeting.objects.get(id=meeting_id)
        rooms = Rooms.objects.filter(channel=meeting)
        messages_chat = Chatmessages.objects.get(channel = meeting)
        messages_chat  = [sms for sms in messages_chat.messages_chat]#.messages_chat
        print("==="*5, messages_chat, "==="*5)
        initial = request.user.username[0].upper()
        context = {"meeting_id": meeting, "rooms": rooms, "host": meeting.host, 'messages_chat': messages_chat, "initial": initial} 
        return render(request, "home.html", context)
    
    return render(request, "home.html")

def join_meeting(request):

    if request.method == 'POST':
        entered_password = request.POST.get('password')
        name = request.POST.get('name')
       
        try: 
            meeting = Meeting.objects.get(name=name)
            if entered_password == meeting.password:
                if not meeting.users.filter(id=request.user.id).exists():
                    # Ajouter l'utilisateur s'il n'existe pas déjà
                    meeting.users.add(request.user)
                    meeting.save()
                return redirect('home', meeting_id=meeting.id)  # Rediriger vers la réunion
        except:
           
            messages.info(request, "dentifiant ou mot de passe incorrect ! ")
            # Mot de passe incorrect
            return render(request, 'index.html', {'meeting': 'Mot de passe incorrect'})
   
    return render(request, 'index.html')



from .forms import *

'''def create_room(request):
    if request.method == 'POST':
        form = RoomForm(request.POST)
        if form.is_valid():
            room = form.save(commit=False)
            room.host = request.user  # Assigner l'utilisateur connecté comme hôte
            room.save()
            return redirect('room_detail', room_id=room.id)  # Rediriger vers la page de la salle
    else:
        form = RoomForm()
    return render(request, 'create_room.html', {'form': form})
'''



@csrf_exempt  # Permet des tests sans token CSRF (désactiver en production si non nécessaire)
def create_room(request, channel_name):
    if request.method == 'POST':
        print("Create Room ", channel_name )
        meeting = Meeting.objects.get(name=channel_name)
        selected_choice = request.POST.get('unique_choice')  # Récupère la valeur choisie
        print('select_c')
        # Récupère la valeur choisie
        if selected_choice =='manuel':
            
            # Compte les salles liées à ce canal
            room_count = Rooms.objects.filter(channel=meeting).count()
            nombre_de_salle = int(request.POST.get('nombre_de_salle'))
            print("roomcounr: ", room_count)
                # Génère le nom de la nouvelle salle
            for manual_room in range(1, nombre_de_salle+1):
                room_name = f"{meeting.name}_salle{room_count + manual_room }"
                roomadd = Rooms.objects.create(
                    name=room_name,
                    host= request.user,
                    channel=meeting, 
                    
                )
                roomadd.users.add(request.user)
                roomadd.save()
            rooms = Rooms.objects.filter(channel=meeting).values()
            return JsonResponse({
                'message': 'Choix soumis avec succès.',
                'selected_choice': selected_choice,
                 'rooms': list(rooms),
            })
        elif selected_choice =='automatique':
             select_user= 0
             participant_par_salle = int(request.POST.get('participant_par_salle'))
             liste_users = [user_name for  user_name in meeting.users.all()] 
             num_salles = (len(liste_users))//participant_par_salle
             if ((len(liste_users))%participant_par_salle) != 0:
                  num_salles +=1
             room_count = Rooms.objects.filter(channel=meeting).count()
             print("roomcounr: ", room_count, liste_users, num_salles)
                # Génère le nom de la nouvelle salle
             for i_room in range(1, num_salles+1):
                print("val: ", i_room)
                room_name = f"{meeting.name}_salle{room_count + i_room}"
                print("val: ", room_name)
                
                roomadd = Rooms.objects.create(
                    name=room_name,
                    host= request.user,
                    channel=meeting,    
                )
                try:
                    roomadd.users.add(*liste_users[:participant_par_salle+1])
                    liste_users = liste_users[participant_par_salle+1:]
                    roomadd.save()
                except:
                    roomadd.users.add(*liste_users[:])
                    
                    roomadd.save()
             rooms = Rooms.objects.filter(channel=meeting).values()
             print("rooms: ", rooms)
             return JsonResponse({
                'message': 'Choix soumis avec succès.',
                'selected_choice': selected_choice,
                'rooms': list(rooms),
            })
            
            
        return JsonResponse({'error': 'Aucun choix sélectionné.'}, status=400)
    return JsonResponse({'error': 'Méthode non autorisée.'}, status=405)

from django.http import JsonResponse
from .models import Rooms

def get_rooms(request, channel_name):
    meeting = Meeting.objects.get(name=channel_name)
    #rooms = Rooms.objects.filter(channel=meeting).values()
    rooms = Rooms.objects.filter(channel=meeting, users__id=request.user.id)
    #print(rooms)
    room_data = [{"name": room.name} for room in rooms]
    
    return JsonResponse({"rooms": room_data})


@csrf_exempt  # Permet des tests sans token CSRF (désactiver en production si non nécessaire)
def join_room(request, meeting_id):
    if request.method == 'POST':
        room_name = request.POST.get('room_name')  # Récupère la valeur choisie
        # Récupère la valeur choisie
        
        meeting = Meeting.objects.get(id=meeting_id)
        # Compte les salles liées à ce canal
        room = Rooms.objects.filter(channel=meeting, name=room_name)

        room.users.add(request.user)
        return JsonResponse({
            'room': room,
        })
        #return JsonResponse({'error': 'Aucun choix sélectionné.'}, status=400)
    return JsonResponse({'error': 'Méthode non autorisée.'}, status=405)


@csrf_exempt
def ask_ia(request):
    
    if request.method == 'POST':
        print("Ok")
        #print(request.body["message"])
        #try:
        data = json.loads(request.body)
        user_message = data.get('message', '')
        # Remplacez ceci par l'appel réel à votre modèle RAG
        print(user_message)
        ia_response= chat(question= user_message)
        #ia_response = f"Voici une réponse générée pour : {user_message}, {text}"
        return JsonResponse({'response': ia_response})
        #except:
        #    return JsonResponse({'response': "System error"})
    
    return render(request, "chat.html")


import openai

def chat(question):
    openai.api_type = "azure"
    openai.api_key = "6xv3rz6Asc5Qq86B8vqjhKQzSTUZPmCcSuDm5CLEV5dj9m8gTHlNJQQJ99AKACYeBjFXJ3w3AAABACOGyHXT"
    openai.api_base = "https://chatlearning.openai.azure.com/"  # Remplacez par votre URL Azure
    openai.api_version = "2023-12-01-preview"

    prompt = (
       f"Tu es un concepteur pour repondre aux questions des utilisateurs sur ton application d'appel video capable \n\n"
        f"de fournir de faire l'appel video dans différentes langues en traduisant les voix des utilisateurs par des\n\n "
        f"voix artificielles.\n\n"
        f"L'étudiant pose la question suivante : {question}\n\n"
        f"Fournissez une réponse détaillée, pratique et facile à comprendre, comme si vous étiez l'assistant pour le support "
        f"Répondez en français."
    )

    # Appel à l'API GPT
    response = openai.ChatCompletion.create(
        engine="gpt-35-turbo",  # Remplacez par le nom de votre déploiement Azure
        messages=[
            {"role": "system", "content": "Vous êtes un expert en cuisine et un instructeur professionnel."},
            {"role": "user", "content": prompt},
        ]
    )

    return response['choices'][0]['message']['content']





def upload_file(request):
    if request.method == 'POST' and request.FILES['file']:
        file = request.FILES['file']
        fs = FileSystemStorage()
        filename = fs.save(file.name, file)
        file_url = fs.url(filename)
        
        # Notifier via WebSocket
        # Vous pouvez appeler un consumer ici ou utiliser un autre moyen pour envoyer une notification WebSocket

        return JsonResponse({'file_url': file_url})
    return render(request, 'chat/upload.html')


from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib, ssl

email_address = 'voicetranslator0@gmail.com'
email_password = 'rfqzyhocddgmehbe'

smtp_address = 'smtp.gmail.com'
smtp_port = 465

def emailsender(Subject, html, user_email):
    message = MIMEMultipart("alternative")
    # on ajoute un sujet
    message["Subject"] = Subject
    # un émetteur
    message["From"] = f"VideoCall <{email_address}>"
    # un destinataire
    message["To"] = user_email
    # on crée deux éléments MIMEText 
    html_mime = MIMEText(html, 'html')

    # on attache ces deux éléments 
    message.attach(html_mime)

    # on crée la connexion
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_address, smtp_port, context=context) as server:
        # connexion au compte
        server.login(email_address, email_password)
        # envoi du mail
        server.sendmail(email_address, user_email, message.as_string())





from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains import RetrievalQA,  ConversationalRetrievalChain
from langchain.memory import ConversationBufferMemory
from langchain_openai import OpenAI, ChatOpenAI
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from dotenv import load_dotenv, find_dotenv
_ = load_dotenv(find_dotenv())
openai.api_key ="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"
os.environ["OPENAI_API_KEY"] ="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"

embeddings = OpenAIEmbeddings()

def boat(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        question = data.get('message', '')
        print('La question: ', question)

        llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
        folder_path = os.path.join(settings.MEDIA_ROOT, "videocall_boat")
        vectordb =FAISS.load_local(folder_path, embeddings , allow_dangerous_deserialization=True )
        memory = ConversationBufferMemory(
        memory_key="chat_history",
        output_key="answer",
        return_messages=True
        )
        
        qa = ConversationalRetrievalChain.from_llm(
            llm,
            retriever=vectordb.as_retriever(),
            return_source_documents=True,
            #chain_type_kwargs={"prompt": prompt},
            return_generated_question=True,
            memory=memory,
        
        )
    
        #question = "Qu'est ce que la cuisine?"
        result = qa.invoke({"question": question})
        

        return JsonResponse({'response': result["answer"],})