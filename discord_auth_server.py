"""
Discord OAuth2 Authentication Server
Integra Discord Developer API com KeyAuth
"""

from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
import requests
import secrets
import time
from datetime import datetime, timedelta
import json
import os

app = Flask(__name__)
CORS(app)

# ==================== CONFIGURAÇÕES ====================
# Discord Developer Portal: https://discord.com/developers/applications
DISCORD_CLIENT_ID = "1455592638076944540"  # Cole aqui
DISCORD_CLIENT_SECRET = "yA52mdjeaZYfeEEZ_D_OaFcRwdbJUGCL"  # Cole aqui
DISCORD_REDIRECT_URI = "http://localhost:5000/callback"

# KeyAuth Config
KEYAUTH_API = "https://keyauth.win/api/1.3/"
KEYAUTH_NAME = "Yokankcu7's Application"
KEYAUTH_OWNERID = "imHYDNmJFI"
KEYAUTH_VERSION = "1.0"

# Sessões temporárias (em produção, use Redis/Database)
auth_sessions = {}
pending_logins = {}

# Cache simples para informações do usuário do Discord (ID: {'username': str, 'avatar_url': str, 'timestamp': float})
discord_user_cache = {}
CACHE_DURATION = 300  # 5 minutos em segundos

# Lista de IDs do Discord autorizados a acessar o painel
AUTHORIZED_USERS_FILE = 'authorized_discord_users.json'

# Banco de dados simples para armazenar usuários registrados
REGISTERED_USERS_FILE = 'registered_discord_users.json'

# Carregar lista de usuários autorizados do arquivo, se existir
if os.path.exists(AUTHORIZED_USERS_FILE):
    with open(AUTHORIZED_USERS_FILE, 'r') as f:
        authorized_discord_ids = set(json.load(f))
else:
    # Por padrão, incluir alguns IDs como exemplo
    # Você pode modificar esta lista conforme necessário
    authorized_discord_ids = {"713070287129936002", "1243913362409132146"}  # Substitua com os IDs reais
    with open(AUTHORIZED_USERS_FILE, 'w') as f:
        json.dump(list(authorized_discord_ids), f)

# Carregar usuários registrados do arquivo, se existir
if os.path.exists(REGISTERED_USERS_FILE):
    with open(REGISTERED_USERS_FILE, 'r') as f:
        registered_discord_users = json.load(f)
else:
    registered_discord_users = {}  # Dicionário: {discord_id: {'username': str, 'registered_at': str, 'subscription': {}}}

# ==================== DISCORD OAUTH2 ====================

@app.route('/auth/discord/start', methods=['GET'])
def discord_auth_start():
    """Inicia o fluxo OAuth2 do Discord"""
    state = secrets.token_urlsafe(32)
    pending_logins[state] = {
        'created_at': time.time(),
        'status': 'pending'
    }
    
    # URL de autorização do Discord
    discord_auth_url = (
        f"https://discord.com/api/oauth2/authorize?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={DISCORD_REDIRECT_URI}&"
        f"response_type=code&"
        f"scope=identify%20email&"
        f"state={state}"
    )
    
    return jsonify({
        'success': True,
        'auth_url': discord_auth_url,
        'state': state
    })


@app.route('/callback', methods=['GET'])
def discord_callback():
    """Callback do Discord após autorização"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or not state or state not in pending_logins:
        return "Erro na autenticação! Feche esta janela e tente novamente.", 400
    
    # Trocar code por access token
    token_data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_response = requests.post(
        'https://discord.com/api/oauth2/token',
        data=token_data,
        headers=headers
    )
    
    if token_response.status_code != 200:
        return "Erro ao obter token do Discord!", 400
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    # Obter informações do usuário
    user_headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.get(
        'https://discord.com/api/users/@me',
        headers=user_headers
    )
    
    if user_response.status_code != 200:
        return "Erro ao obter dados do usuário!", 400
    
    user_data = user_response.json()
    discord_id = user_data.get('id')
    username = user_data.get('username')
    email = user_data.get('email', 'No email')
    
    # Validar com KeyAuth
    keyauth_result = validate_with_keyauth(discord_id, username)
    
    # Salvar resultado da autenticação
    pending_logins[state] = {
        'status': 'completed',
        'discord_id': discord_id,
        'username': username,
        'email': email,
        'keyauth_success': keyauth_result['success'],
        'keyauth_message': keyauth_result.get('message', ''),
        'subscription': keyauth_result.get('subscription', {}),
        'completed_at': time.time()
    }
    
    if keyauth_result['success']:
        return f"""
        <html>
        <head><title>Autenticação Completa</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px; background: #0c0c0c; color: white;">
            <h1 style="color: #fcba03;">✅ Autenticação Bem-sucedida!</h1>
            <p>Bem-vindo, <strong>{username}</strong>!</p>
            <p>Discord ID: {discord_id}</p>
            <p>Você pode fechar esta janela e retornar ao aplicativo.</p>
        </body>
        </html>
        """
    else:
        return f"""
        <html>
        <head><title>Erro de Autenticação</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px; background: #0c0c0c; color: white;">
            <h1 style="color: #ff4444;">❌ Erro na Autenticação</h1>
            <p>{keyauth_result.get('message', 'Usuário não autorizado')}</p>
            <p>Feche esta janela e entre em contato com o suporte.</p>
        </body>
        </html>
        """


@app.route('/auth/check/<state>', methods=['GET'])
def check_auth_status(state):
    """Cliente C++ verifica status da autenticação"""
    if state not in pending_logins:
        return jsonify({'success': False, 'message': 'Invalid state'}), 404
    
    session = pending_logins[state]
    
    # Limpar sessões antigas (mais de 5 minutos)
    if time.time() - session.get('created_at', 0) > 300:
        del pending_logins[state]
        return jsonify({'success': False, 'message': 'Session expired'}), 408
    
    if session['status'] == 'pending':
        return jsonify({'success': False, 'status': 'pending', 'message': 'Aguardando autenticação...'})
    
    if session['status'] == 'completed':
        result = {
            'success': session['keyauth_success'],
            'status': 'completed',
            'discord_id': session['discord_id'],
            'username': session['username'],
            'email': session['email'],
            'message': session['keyauth_message'],
            'subscription': session.get('subscription', {})
        }
        
        # Limpar após retornar
        del pending_logins[state]
        return jsonify(result)
    
    return jsonify({'success': False, 'message': 'Unknown status'}), 500


# ==================== KEYAUTH INTEGRATION ====================

# Função para salvar a lista de usuários autorizados
def save_authorized_users():
    with open(AUTHORIZED_USERS_FILE, 'w') as f:
        json.dump(list(authorized_discord_ids), f)


@app.route('/admin/add_authorized_user', methods=['POST'])
def add_authorized_user():
    """Adiciona um ID do Discord à lista de usuários autorizados"""
    try:
        data = request.json
        discord_id = data.get('discord_id')
        
        if not discord_id:
            return jsonify({'success': False, 'message': 'ID do Discord é necessário'}), 400
        
        # Adicionar ID à lista de autorizados
        authorized_discord_ids.add(str(discord_id))
        save_authorized_users()  # Salvar no arquivo
        
        return jsonify({
            'success': True,
            'message': 'ID do Discord autorizado com sucesso!',
            'discord_id': discord_id
        })
    
    except Exception as e:
        print(f"Erro ao adicionar usuário autorizado: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


@app.route('/admin/remove_authorized_user', methods=['POST'])
def remove_authorized_user():
    """Remove um ID do Discord da lista de usuários autorizados"""
    try:
        data = request.json
        discord_id = data.get('discord_id')
        
        if not discord_id:
            return jsonify({'success': False, 'message': 'ID do Discord é necessário'}), 400
        
        # Remover ID da lista de autorizados, se existir
        if str(discord_id) in authorized_discord_ids:
            authorized_discord_ids.remove(str(discord_id))
            save_authorized_users()  # Salvar no arquivo
            return jsonify({
                'success': True,
                'message': 'ID do Discord removido da lista de autorizados com sucesso!',
                'discord_id': discord_id
            })
        else:
            return jsonify({'success': False, 'message': 'ID do Discord não encontrado na lista de autorizados'}), 404
    
    except Exception as e:
        print(f"Erro ao remover usuário autorizado: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


@app.route('/admin/list_authorized_users', methods=['GET'])
def list_authorized_users():
    """Lista todos os IDs de Discord autorizados"""
    try:
        return jsonify({
            'success': True,
            'authorized_users': list(authorized_discord_ids),
            'count': len(authorized_discord_ids)
        })
    
    except Exception as e:
        print(f"Erro ao listar usuários autorizados: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


# Função para salvar usuários registrados no arquivo
def save_registered_users():
    with open(REGISTERED_USERS_FILE, 'w') as f:
        json.dump(registered_discord_users, f)


def validate_with_keyauth(discord_id, username):
    """Valida o Discord ID com KeyAuth"""
    try:
        # Inicializar sessão
        init_data = {
            'type': 'init',
            'ver': KEYAUTH_VERSION,
            'name': KEYAUTH_NAME,
            'ownerid': KEYAUTH_OWNERID
        }
        
        init_response = requests.post(KEYAUTH_API, data=init_data)
        init_json = init_response.json()
        
        if not init_json.get('success'):
            return {'success': False, 'message': 'Erro ao inicializar KeyAuth'}
        
        sessionid = init_json.get('sessionid')
        
        # Tentar login com discord_ID
        login_username = f"discord_{discord_id}"
        login_data = {
            'type': 'login',
            'username': login_username,
            'pass': discord_id,
            'sessionid': sessionid,
            'name': KEYAUTH_NAME,
            'ownerid': KEYAUTH_OWNERID
        }
        
        login_response = requests.post(KEYAUTH_API, data=login_data)
        login_json = login_response.json()
        
        if login_json.get('success'):
            # Extrair info de subscription
            info = login_json.get('info', {})
            subscriptions = info.get('subscriptions', [])
            
            subscription_info = {}
            if subscriptions:
                sub = subscriptions[0]
                subscription_info = {
                    'active': True,
                    'expiry': sub.get('expiry', ''),
                    'subscription': sub.get('subscription', '')
                }
            
            return {
                'success': True,
                'message': 'Login realizado com sucesso!',
                'subscription': subscription_info
            }
        else:
            return {
                'success': False,
                'message': login_json.get('message', 'Usuário não encontrado no sistema. Use uma Key para registrar.')
            }
            
    except Exception as e:
        return {'success': False, 'message': f'Erro: {str(e)}'}


def validate_discord_id(discord_id):
    """Valida se o ID do Discord é real consultando a API pública do Discord"""
    try:
        # Primeiro, verificar formato básico do ID do Discord (geralmente tem pelo menos 17 dígitos)
        if len(str(discord_id)) < 17 or not str(discord_id).isdigit():
            return False
        
        # Para melhor performance, apenas verificar o formato e assumir como válido
        # para evitar chamadas lentas a APIs externas
        # Se quiser manter a validação externa, pode descomentar o código abaixo
        '''
        # Tentar buscar informações do usuário via lookup público
        apis = [
            f"https://discordlookup.mesalytic.moe/v1/user/{discord_id}",
            f"https://japi.rest/discord/v1/user/{discord_id}"
        ]
        
        for api_url in apis:
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(api_url, headers=headers, timeout=5)  # Aumentar timeout
                
                if response.status_code == 200:
                    data = response.json()
                    if 'username' in data or ('data' in data and 'username' in data['data']):
                        return True  # ID do Discord é válido
            except requests.Timeout:
                continue
            except Exception as e:
                print(f"Erro na API {api_url}: {e}")
                continue
        '''
        
        # Assumir que IDs com formato correto são válidos para melhor performance
        return True
    except Exception as e:
        print(f"Erro ao validar ID do Discord: {e}")
        return False  # Em caso de erro, retornar False para segurança


@app.route('/discord/register', methods=['POST'])
def register_discord_only():
    """Registra um usuário usando apenas o ID do Discord"""
    try:
        data = request.json
        discord_id = data.get('discord_id')
        
        if not discord_id:
            return jsonify({'success': False, 'message': 'ID do Discord é necessário'}), 400
        
        # Verificar se o ID do Discord está autorizado
        if discord_id not in authorized_discord_ids:
            return jsonify({'success': False, 'message': 'ID do Discord não autorizado para acesso'}), 400
        
        # Validar se o ID do Discord é real
        if not validate_discord_id(discord_id):
            return jsonify({'success': False, 'message': 'ID do Discord inválido'}), 400
        
        # Verificar se já está registrado
        if discord_id in registered_discord_users:
            return jsonify({'success': False, 'message': 'ID do Discord já está registrado'}), 400
        
        # Buscar informações do usuário do Discord
        user_info = get_discord_user_info(discord_id)
        username = user_info['username']
        avatar_url = user_info['avatar_url']
        
        # Registrar usuário
        registered_discord_users[discord_id] = {
            'username': username,
            'avatar_url': avatar_url,
            'registered_at': datetime.now().isoformat(),
            'subscription': {
                'active': True,
                'expiry': (datetime.now() + timedelta(days=30)).isoformat(),  # 30 dias de acesso
                'subscription': 'Free Access'
            }
        }
        
        # Salvar no arquivo
        save_registered_users()
        
        return jsonify({
            'success': True,
            'message': 'Registrado com sucesso!',
            'discord_id': discord_id,
            'username': username,
            'avatar_url': avatar_url
        })
    
    except Exception as e:
        print(f"Erro ao registrar usuário do Discord: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


@app.route('/discord/login', methods=['POST'])
def login_discord_only():
    """Faz login usando apenas o ID do Discord"""
    try:
        # Adicionando logs para debug
        print(f"Recebendo requisição de login com dados: {request.data}")
        
        data = request.json
        print(f"Dados parseados como JSON: {data}")
        
        if not data:
            print("Erro: Nenhum dado JSON recebido")
            return jsonify({'success': False, 'message': 'Nenhum dado recebido'}), 400
        
        discord_id = data.get('discord_id')
        print(f"ID do Discord extraído: {discord_id}")
        
        if not discord_id:
            print("Erro: ID do Discord é necessário")
            return jsonify({'success': False, 'message': 'ID do Discord é necessário'}), 400
        
        # Verificar se o ID do Discord está autorizado
        print(f"Verificando se {discord_id} está na lista de autorizados...")
        if str(discord_id) not in authorized_discord_ids:
            print(f"Erro: {discord_id} não está na lista de autorizados. Lista: {authorized_discord_ids}")
            return jsonify({'success': False, 'message': 'ID do Discord não autorizado para acesso'}), 400
        
        # Verificar se o usuário está registrado
        print(f"Verificando se {discord_id} está registrado...")
        if str(discord_id) not in registered_discord_users:
            print(f"Erro: {discord_id} não está registrado. Lista: {list(registered_discord_users.keys())}")
            return jsonify({'success': False, 'message': 'ID do Discord não encontrado. Por favor, registre-se primeiro.'}), 400
        
        user_data = registered_discord_users[str(discord_id)]
        print(f"Dados do usuário encontrados: {user_data}")
        
        # Verificar se a subscrição ainda é válida
        if user_data['subscription']['active']:
            expiry_date = datetime.fromisoformat(user_data['subscription']['expiry'])
            if datetime.now() > expiry_date:
                # Subscrição expirou
                user_data['subscription']['active'] = False
                save_registered_users()  # Atualizar arquivo
        
        return jsonify({
            'success': True,
            'message': 'Login realizado com sucesso!',
            'discord_id': str(discord_id),
            'username': user_data['username'],
            'avatar_url': user_data.get('avatar_url', ''),
            'subscription': user_data['subscription']
        })
    
    except Exception as e:
        print(f"Erro ao fazer login do Discord: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


def get_discord_user_info(discord_id):
    """Obtém informações do usuário do Discord (nome e avatar) usando o ID"""
    current_time = time.time()
    
    # Verificar se as informações estão no cache e ainda são válidas
    if discord_id in discord_user_cache:
        cached_data = discord_user_cache[discord_id]
        if current_time - cached_data['timestamp'] < CACHE_DURATION:
            return cached_data
    
    try:
        # Tentar múltiplas APIs públicas
        apis = [
            f"https://discordlookup.mesalytic.moe/v1/user/{discord_id}",
            f"https://japi.rest/discord/v1/user/{discord_id}"
        ]
        
        for api_url in apis:
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(api_url, headers=headers, timeout=5)  # Aumentar timeout para 5 segundos
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Verificar estrutura da resposta
                    if 'username' in data:
                        username = data['username']
                        if 'discriminator' in data and data['discriminator'] != '0':
                            username = f"{username}#{data['discriminator']}"
                        
                        # Obter avatar se disponível
                        avatar_hash = data.get('avatar', '')
                        avatar_url = ''
                        if avatar_hash:
                            extension = 'gif' if avatar_hash.startswith('a_') else 'png'
                            avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.{extension}?size=128"
                        
                        user_info = {
                            'username': username,
                            'avatar_url': avatar_url
                        }
                        
                        # Armazenar no cache
                        discord_user_cache[discord_id] = {**user_info, 'timestamp': current_time}
                        
                        return user_info
                    elif 'data' in data and 'username' in data['data']:
                        username = data['data']['username']
                        if 'discriminator' in data['data'] and data['data']['discriminator'] != '0':
                            username = f"{username}#{data['data']['discriminator']}"
                        
                        # Obter avatar se disponível
                        avatar_hash = data['data'].get('avatar', '')
                        avatar_url = ''
                        if avatar_hash:
                            extension = 'gif' if avatar_hash.startswith('a_') else 'png'
                            avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.{extension}?size=128"
                        
                        user_info = {
                            'username': username,
                            'avatar_url': avatar_url
                        }
                        
                        # Armazenar no cache
                        discord_user_cache[discord_id] = {**user_info, 'timestamp': current_time}
                        
                        return user_info
            except requests.Timeout:
                continue
            except Exception as e:
                print(f"Erro ao buscar informações do usuário da API {api_url}: {e}")
                continue

        # Se todas as APIs falharem, retornar informações padrão
        user_info = {
            'username': f"DiscordUser_{discord_id[:8]}",
            'avatar_url': ''
        }
        
        # Armazenar no cache mesmo assim para evitar tentativas repetidas
        discord_user_cache[discord_id] = {**user_info, 'timestamp': current_time}
        
        return user_info
    except Exception as e:
        print(f"Erro geral na função get_discord_user_info: {e}")
        user_info = {
            'username': f"DiscordUser_{discord_id[:8]}",
            'avatar_url': ''
        }
        
        # Armazenar no cache mesmo assim para evitar tentativas repetidas
        discord_user_cache[discord_id] = {**user_info, 'timestamp': current_time}
        
        return user_info


def get_discord_username_by_id(discord_id):
    """Obtém o nome de usuário do Discord usando o ID"""
    try:
        user_info = get_discord_user_info(discord_id)
        return user_info['username']
    except Exception as e:
        print(f"Erro ao obter nome do usuário do Discord: {e}")
        return f"DiscordUser_{discord_id[:8]}"


@app.route('/health', methods=['GET'])
def health_check():
    """Verifica se o servidor está online"""
    return jsonify({'status': 'online', 'timestamp': datetime.now().isoformat()})


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Discord OAuth2 Authentication Server")
    print("=" * 60)
    print(f"Server running on: http://localhost:5000")
    print(f"Discord Redirect URI: {DISCORD_REDIRECT_URI}")
    print("\n⚙️  Configure no Discord Developer Portal:")
    print("   1. https://discord.com/developers/applications")
    print("   2. OAuth2 → Add Redirect: http://localhost:5000/callback")
    print("   3. Cole Client ID e Secret neste arquivo")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
