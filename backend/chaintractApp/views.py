from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from .forms import DocumentUploadForm
from .models import Document, Signature, UserProfile
import hashlib
import secrets
from web3.auto import w3
from eth_account.messages import encode_defunct
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404

def index(request):
    return HttpResponse("index")

@login_required
def upload_document(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            title = form.cleaned_data['title']
            signee_address = form.cleaned_data['signee_address']

            hasher = hashlib.sha256()
            for chunk in uploaded_file.chunks():
                hasher.update(chunk)
            file_hash = hasher.hexdigest()

            document = Document.objects.create(
                owner=request.user,
                # signee=signee,
                signee_address=signee_address,
                title=title,
                file=uploaded_file,
                file_hash=file_hash
            )

            # return HttpResponse(f"Document '{document.title}' uploaded successfully! Hash: {file_hash}")
            return redirect('chaintractApp:document_list_owned')

    else: # GET
        form = DocumentUploadForm()

    return render(request, 'chaintractApp/upload_document.html', {'form': form})

@login_required
def document_list_owned(request):
    documents = Document.objects.filter(owner=request.user).order_by('-uploaded_at')
    context = {
        'documents': documents
    }
    return render(request, 'chaintractApp/document_list_owned.html', context)

@login_required
def document_list_to_sign(request):
    try:
        user_profile = request.user.profile
        if not user_profile or not user_profile.eth_address:
             return render(request, 'chaintractApp/document_list_to_sign.html', {'documents': [], 'error': 'Please connect your Ethereum wallet.'})

        documents = Document.objects.filter(
            signee_address__iexact=user_profile.eth_address,
            status='pending'
        ).order_by('-uploaded_at')
        context = {
            'documents': documents
        }
        return render(request, 'chaintractApp/document_list_to_sign.html', context)
    except UserProfile.DoesNotExist:
         return render(request, 'chaintractApp/document_list_to_sign.html', {'documents': [], 'error': 'User profile not found. Please log in again via Metamask.'})

# todo
LOGIN_SIGNATURE_MESSAGE = "Sign this message to verify your wallet address and log in to ChainTract."

@csrf_exempt
def get_message_to_sign(request):
   return JsonResponse({'message': LOGIN_SIGNATURE_MESSAGE})

@csrf_exempt
def login_with_signature(request):
    if request.method == 'POST':
        address = request.POST.get('address')
        signature = request.POST.get('signature')

        if not all([address, signature]):
            return JsonResponse({'error': 'Missing address or signature.'}, status=400)

        if not w3.is_address(address):
             return JsonResponse({'error': 'Invalid address provided.'}, status=400)

        message_to_verify = encode_defunct(text=LOGIN_SIGNATURE_MESSAGE)
        signer_address = w3.eth.account.recover_message(message_to_verify, signature=signature)

        if signer_address.lower() == address.lower():
            try:
                user = None
                profile = None
                try:
                    profile = UserProfile.objects.select_related('user').get(eth_address__iexact=address)
                    user = profile.user
                except UserProfile.DoesNotExist:
                    username = f'user_{address[:6]}_{address[-4:]}' 
                    counter = 1
                    base_username = username
                    while User.objects.filter(username=username).exists():
                        username = f"{base_username}_{counter}"
                        counter += 1

                    user = User.objects.create_user(username=username)
                    try:
                        profile = UserProfile.objects.get(user=user)
                        profile.eth_address = address
                        profile.save()
                    except UserProfile.DoesNotExist:
                         print(f"Error: Profile for newly created user {username} not found by signal.")
                         raise Exception("UserProfile auto-creation failed.")


                if not user or not profile:
                     raise Exception("User or Profile could not be established.")

                login(request, user)
                return JsonResponse({'success': True, 'username': user.username})

            except Exception as e:
                print(f"Login Exception: {e}") 
                return JsonResponse({'error': f'Login process failed: {str(e)}'}, status=500)
        else:
            return JsonResponse({'error': 'Invalid signature.'}, status=403)

    return JsonResponse({'error': 'POST request required.'}, status=405)

@login_required
def user_logout(request):
    logout(request)
    # return redirect('chaintractApp:login') 
    return HttpResponse("Logged out")

@login_required
def sign_document(request, document_id):
    document = get_object_or_404(Document, pk=document_id)
    user_profile = request.user.profile 

    if not user_profile.eth_address or document.signee_address.lower() != user_profile.eth_address.lower():
        return HttpResponse("You are not authorized to sign this document.", status=403)

    if document.status != 'pending':
        return HttpResponse(f"This document is already {document.get_status_display()}.")

    if request.method == 'POST':
        try:
            document.status = 'signed'
            document.save()

            signature = Signature.objects.create(
                document=document,
                signer_address=user_profile.eth_address
            )

            blockchain_tx_hash_placeholder = f'0x_placeholder_{document.id}_{secrets.token_hex(4)}'
            signature.blockchain_tx_hash = blockchain_tx_hash_placeholder 
            signature.save()

            return redirect('chaintractApp:document_list_to_sign')

        except Exception as e:
            print(f"Signing Error: {e}")
            context = {
                'document': document,
                'error': f'An error occurred during signing: {e}'
            }
            return render(request, 'chaintractApp/sign_document.html', context)

    context = {
        'document': document,
        'file_hash': document.file_hash
    }
    return render(request, 'chaintractApp/sign_document.html', context)
