from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, FileResponse
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
from .utils import register_document_on_chain, record_signature_on_chain, check_if_deal_is_on_chain
from django.conf import settings
import boto3

s3_client = boto3.client(
    's3',
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_REGION
)

def home(request):
    return render(request, 'chaintractApp/home.html')

def index(request):
    return redirect('chaintractApp:home')

@login_required
def upload_document(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            title = form.cleaned_data['title']
            signee_address = form.cleaned_data['signee_address']

            file_content = uploaded_file.read()  
            uploaded_file.seek(0)  

            hasher = hashlib.sha256()
            hasher.update(file_content)
            file_hash_hex = hasher.hexdigest()
            file_hash_bytes = bytes.fromhex(file_hash_hex)  

            document = Document.objects.create(
                owner=request.user,
                signee_address=signee_address,
                title=title,
                file=uploaded_file,
                file_hash=file_hash_hex
            )

            try:
                if settings.CONTRACT_ADDRESS:  
                    tx_receipt = register_document_on_chain(file_hash_bytes)
                    document.on_chain_registration_tx = tx_receipt.transactionHash.hex()
                    document.save()
                    print(f"Document {document.id} registered on chain. Tx: {tx_receipt.transactionHash.hex()}")
                else:
                    print("CONTRACT_ADDRESS not set. Skipping on-chain registration.")
            except Exception as e:
                print(f"Error registering document on chain: {e}")

            return redirect('chaintractApp:document_list_owned')

    else:  # GET
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
                    username = address.lower()
                    counter = 1
                    base_username = username
                    while User.objects.filter(username=username).exists():
                        username = f"{base_username}_{counter}"
                        counter += 1

                    user = User.objects.create_user(username=username)
                    profile = UserProfile.objects.create(user=user, eth_address=address)

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
    return redirect('chaintractApp:login') 

@login_required
def document_list_all(request):
    user = request.user
    owned_documents = Document.objects.filter(owner=user)
    
    documents_to_sign_or_signed = Document.objects.none() 
    try:
        user_profile = user.profile
        if user_profile and user_profile.eth_address:
            documents_to_sign_or_signed = Document.objects.filter(
                signee_address__iexact=user_profile.eth_address
            )
    except UserProfile.DoesNotExist:
        pass

    all_documents = (owned_documents | documents_to_sign_or_signed).distinct().order_by('-uploaded_at')
    
    context = {
        'documents': all_documents,
        'user_profile_exists': hasattr(user, 'profile') and user.profile.eth_address is not None
    }
    return render(request, 'chaintractApp/document_list_all.html', context)

@login_required
def view_document_file(request, document_id):
    document = get_object_or_404(Document, pk=document_id)
    user = request.user
    user_profile = getattr(user, 'profile', None)

    is_owner = (document.owner == user)
    is_signee = False
    if user_profile and user_profile.eth_address:
        is_signee = (document.signee_address and \
                     document.signee_address.lower() == user_profile.eth_address.lower())

    if not (is_owner or is_signee):
        return HttpResponse("You are not authorized to view this document.", status=403)

    if not document.file or not document.file.name:
        return HttpResponse("File not found for this document.", status=404)

    try:
        s3_object = s3_client.get_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=document.file.name)
        
        response = FileResponse(s3_object['Body'], content_type=s3_object.get('ContentType', 'application/octet-stream'))
        response['X-Frame-Options'] = 'SAMEORIGIN' 
        response['Content-Disposition'] = f'inline; filename="{document.file.name.split('/')[-1]}"' 
        return response
    except Exception as e:
        print(f"Error fetching file from S3: {e}")
        return HttpResponse("Error fetching file.", status=500)

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
            document_hash_bytes = bytes.fromhex(document.file_hash)
            signer_eth_address = user_profile.eth_address

            if settings.CONTRACT_ADDRESS:  
                tx_receipt = record_signature_on_chain(document_hash_bytes, signer_eth_address)
                blockchain_tx_hash = tx_receipt.transactionHash.hex()
                print(f"Signature for document {document.id} by {signer_eth_address} recorded on chain. Tx: {blockchain_tx_hash}")
            else:
                print("CONTRACT_ADDRESS not set. Skipping on-chain signature.")
                blockchain_tx_hash = f'0x_placeholder_offchain_{document.id}_{secrets.token_hex(4)}'  

            document.status = 'signed'
            document.save()

            signature = Signature.objects.create(
                document=document,
                signer_address=signer_eth_address,
                blockchain_tx_hash=blockchain_tx_hash
            )

            return redirect('chaintractApp:document_list_to_sign')

        except Exception as e:
            print(f"Signing Error: {e}")
            context = {
                'document': document,
                'error': f'An error occurred during signing: {e}',
                'file_hash': document.file_hash
            }
            return render(request, 'chaintractApp/sign_document.html', context)

    on_chain_status = "N/A (Contract not configured)"
    if settings.CONTRACT_ADDRESS:
        try:
            is_signed_on_chain = check_if_deal_is_on_chain(bytes.fromhex(document.file_hash), user_profile.eth_address)
            on_chain_status = "Signed on-chain" if is_signed_on_chain else "Not signed on-chain"
        except Exception as e:
            print(f"Error checking on-chain status: {e}")
            on_chain_status = "Error checking status"

    context = {
        'document': document,
        'file_hash': document.file_hash,
        'on_chain_status': on_chain_status
    }
    return render(request, 'chaintractApp/sign_document.html', context)

def verify_document(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES, use_title_and_signee=False)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            file_content = uploaded_file.read()
            hasher = hashlib.sha256()
            hasher.update(file_content)
            file_hash_hex = hasher.hexdigest()
            file_hash_bytes = bytes.fromhex(file_hash_hex)

            from .utils import get_contract_instance
            contract = get_contract_instance()
            document_owner = None
            try:
                if contract:
                    document_owner = contract.functions.getDocumentOwner(file_hash_bytes).call()
            except Exception as e:
                print(f"Blockchain verification error: {e}")
                document_owner = None

            is_registered_on_chain = document_owner and document_owner != '0x0000000000000000000000000000000000000000'

            matching_document = Document.objects.filter(file_hash=file_hash_hex).first()

            return render(request, 'chaintractApp/verify_document_result.html', {
                'file_hash': file_hash_hex,
                'is_registered_on_chain': is_registered_on_chain,
                'document_owner': document_owner,
                'matching_document': matching_document
            })
    else:
        form = DocumentUploadForm(use_title_and_signee=False)
    return render(request, 'chaintractApp/verify_document_form.html', {'form': form})

def signup_view(request):
    return render(request, 'chaintractApp/signup.html')
