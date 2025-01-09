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
               message = f"""
               Hi {username},
               Are you having trouble signing in?

               Resetting your password is easy.
               Just click on the url below and follow the instructions.
               We will have you up and running in no time.


              {current_host}/updatepassword/{token}/{uid}/

               Note that this link is valid for 1 hour.

               If you did not make this request then please ignore this email. 
               
               Thanks,
               VideoCall Authentication
               """
               
            
               #message = mark_safe(render_to_string("emailpsswdreset.html", {}))
               
               email = EmailMessage(Subject,
                             message,
                             f"VideoCall <{settings.EMAIL_HOST}>",
                             [user.email])

               email.send()
               messages.success(request, f"We have send a reset password email to {user.email}, open it and follow the instructions !",)
          else:
               print("User not exist")
               messages.error(request,"L'email ne correspond à aucun compte, veuillez vérifier et reessayer.")
     return render(request, "account/forgot_password.html")


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
                    Cher(e) {username},

                    Nous sommes ravis de t’accueillir sur videoCall ! 🎉

                    Ton compte a été créé avec succès, et tu es maintenant prêt(e) à explorer l'univers passionnant des appels vidéo multilingues. Grâce à notre plateforme, tu peux te connecter avec des personnes du monde entier et profiter de la traduction vocale en temps réel lors de tes appels vidéo.

                    Voici quelques fonctionnalités incroyables que tu peux découvrir dès maintenant :

                    - Communique avec des utilisateurs parlant différentes langues, avec ta voix instantanément traduite dans la langue de ton interlocuteur.
                    - Brise les barrières linguistiques et échange facilement avec des personnes parlant français, anglais, espagnol, et bien d’autres !
                    - Profite d’une traduction fluide et en temps réel grâce à notre technologie IA avancée.
                    - Explore une large sélection de langues pour une expérience de communication véritablement mondiale.

                    Nous sommes impatients de t’aider à connecter avec le monde entier de manière inédite. Si tu as des questions ou besoin d’assistance, n’hésite pas à nous contacter à [ton adresse e-mail] ou à visiter notre page de support.

                    Encore une fois, bienvenue sur videoCall ! Nous sommes ravis de t’avoir parmi nous.

                    Cordialement,  
                    L’équipe videoCall
                    """

                    email = EmailMessage(subject,
                             email_message,
                             f"VideoCall <{settings.EMAIL_HOST}>",
                             [user.email])

                    email.send()
                    mess = f"Welcome {user.username}, Your account is create successfully, to active your account, get you verification code in your email boss at {user.email}"
                        
                    messages.info(request, mess)

                    verification_code, created = VerificationCode.objects.get_or_create(user=user)
                    verification_code.generate_code()
                    print(verification_code.code)
                    
                    code = EmailMessage(
                        'Votre code de vérification ',
                        f'Bonjour,\n\nVotre code de vérification pour activer votre compte sur videoCall est : {verification_code.code}\n\nMerci de l\'utiliser pour valider votre inscription.',
                        f"videoCall <{settings.EMAIL_HOST}>",
                        [user.email]
                    )


                    code.send()
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
        return redirect('home', meeting_id=meeting.id)
        #return redirect('join_meeting', meeting_id=meeting.id)
    return render(request, 'create_meeting.html')


@login_required
def home(request, meeting_id=None):
    if meeting_id:
        meeting = Meeting.objects.get(id=meeting_id)
        rooms = Rooms.objects.filter(channel=meeting)
        context = {"meeting_id": meeting, "rooms": rooms, "host": meeting.host} 
        return render(request, "home.html", context)
    return render(request, "home.html")

def join_meeting(request):

    if request.method == 'POST':
        entered_password = request.POST.get('password')
        name = request.POST.get('name')
        meeting = Meeting.objects.get(name=name)
        if entered_password == meeting.password:
            if not meeting.users.filter(id=request.user.id).exists():
                # Ajouter l'utilisateur s'il n'existe pas déjà
                meeting.users.add(request.user)
            return redirect('home', meeting_id=meeting.id)  # Rediriger vers la réunion
        else:
            # Mot de passe incorrect
            return render(request, 'join_meeting.html', {'meeting': meeting, 'error': 'Mot de passe incorrect'})

    return render(request, 'join_meeting.html', {'meeting': meeting})



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
        print("Create Room ", )
        selected_choice = request.POST.get('unique_choice')  # Récupère la valeur choisie
        # Récupère la valeur choisie
        if selected_choice =='automatique':
            meeting = Meeting.objects.get(name=channel_name)
            # Compte les salles liées à ce canal
            room_count = Rooms.objects.filter(channel=meeting).count()
            print("roomcounr: ", room_count)
                # Génère le nom de la nouvelle salle
            room_name = f"{meeting.name}_salle{room_count + 1}"
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
        return JsonResponse({'error': 'Aucun choix sélectionné.'}, status=400)
    return JsonResponse({'error': 'Méthode non autorisée.'}, status=405)


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

