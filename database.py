import json
import os

from typing import Any, cast

# Json files global
USERS_FILE = 'users.json'
MESSAGES_FILE = 'messages.json'

# Direct Json handeling

def load_json(filepath):
    if not os.path.exists(filepath):
        return {} if filepath == USERS_FILE else []
    with open(filepath, 'r') as f:
        return json.load(f)

def save_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
        
        

# Handeling users
def load_users() -> dict[str, dict[str, Any]]:
    temp = load_json(USERS_FILE)
    return cast(dict[str, dict[str, Any]], temp)

def save_users(users_data):
    save_json(USERS_FILE, users_data)
    
    
# Handeling messages
def load_messages() -> list[dict[str, Any]]:
    temp = load_json(MESSAGES_FILE)
    return cast(list[dict[str, Any]], temp)

def save_message(message_data):
    messages = load_messages() 
    messages.append(message_data)
    save_json(MESSAGES_FILE, messages)