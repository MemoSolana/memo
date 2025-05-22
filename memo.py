from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.instruction import Instruction
from solders.transaction import Transaction
from solders.message import Message
from solana.rpc.api import Client
import base64
import base58
import os
import traceback

app = FastAPI()

PHANTOM_EXPORTED_PRIVATE_KEY = "5CVyKvkgKrMhYDMQCzLr24BwGueZ9bameGViisv1yFF9kGmAxFKSYUb1edAD6rhwPN4jdjbbd1GVKyYaFqLePSek"

try:
    decoded_key = base58.b58decode(PHANTOM_EXPORTED_PRIVATE_KEY)
except Exception:
    try:
        decoded_key = base64.b64decode(PHANTOM_EXPORTED_PRIVATE_KEY)
    except Exception:
        raise ValueError("Invalid private key format. Use Base58 or Base64.")

SENDER_KEYPAIR = Keypair.from_bytes(decoded_key)

SHARED_SECRET_KEY = b"0123456789abcdef0123456789abcdef"
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

client = Client(SOLANA_RPC_URL)


def xor_cipher(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def encrypt_message(message: str, key: bytes) -> str:
    ciphertext = xor_cipher(message.encode(), key)
    return base64.b64encode(ciphertext).decode()


def decrypt_message(encrypted_b64: str, key: bytes) -> str:
    try:
        encrypted_b64 += '=' * (-len(encrypted_b64) % 4)
        ciphertext = base64.b64decode(encrypted_b64)
        return xor_cipher(ciphertext, key).decode()
    except Exception as e:
        raise ValueError("Invalid encrypted data or key") from e


class EncryptSendRequest(BaseModel):
    message: str
    recipient_wallet: str


class DecryptRequest(BaseModel):
    encrypted_message: str


@app.post("/encrypt_send")
async def encrypt_and_send_memo(request: EncryptSendRequest):
    try:
        encrypted = encrypt_message(request.message, SHARED_SECRET_KEY)

        blockhash_response = client.get_latest_blockhash()
        recent_blockhash = blockhash_response.value.blockhash

        instruction = Instruction(
            program_id=MEMO_PROGRAM_ID,
            accounts=[],
            data=encrypted.encode()
        )

        message = Message(
            instructions=[instruction],
            payer=SENDER_KEYPAIR.pubkey()
        )

        transaction = Transaction(
            from_keypairs=[SENDER_KEYPAIR],
            message=message,
            recent_blockhash=recent_blockhash
        )

        signed_tx = bytes(transaction)
        response = client.send_raw_transaction(signed_tx)

        return {
            "tx_signature": str(response.value),
            "encrypted_message": encrypted
        }
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/decrypt")
def decrypt_api(request: DecryptRequest):
    try:
        decrypted = decrypt_message(request.encrypted_message, SHARED_SECRET_KEY)
        return {"decrypted_message": decrypted}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail="Decryption failed: " + str(e))