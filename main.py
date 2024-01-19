import hashlib
import time
import json
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

logging.basicConfig(level=logging.INFO)

class Transaction:
    transaction_count = 0

    def __init__(self, crypto_name, sender, receiver, amount, sender_private_key):
        self.crypto_name = crypto_name
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.transaction_id = Transaction.transaction_count
        self.fee_percentage = 0.001
        self.fee = (amount * self.fee_percentage) / 100
        self.total_amount = amount + self.fee
        self.signature = self.generate_signature(sender_private_key)

        Transaction.transaction_count += 1

    def generate_signature(self, private_key):
        data = f"{self.crypto_name}{self.sender}{self.receiver}{self.amount}{self.fee}".encode('utf-8')
        private_key = ec.generate_private_key(ec.SECP256R1())
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.current_token_supply = 0

    def create_genesis_block(self):
        return Block(0, "0", int(time.time()), [], self.calculate_hash(0, "0", int(time.time()), []))

    def create_new_block(self, transactions, miner_reward):
        index = len(self.chain)
        previous_block = self.chain[-1]
        timestamp = int(time.time())
        transactions.append(miner_reward)
        hash_value = self.calculate_hash(index, previous_block.hash, timestamp, transactions)
        return Block(index, previous_block.hash, timestamp, transactions, hash_value)

    def check_balance(self, user):
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender == user:
                    balance -= transaction.total_amount
                elif transaction.receiver == user:
                    balance += transaction.amount
        return balance

    def process_transaction(self, sender, receiver, amount, sender_private_key):
        try:
            transaction = Transaction("BOZ", sender, receiver, amount, sender_private_key)
            if self.verify_signature(sender_private_key, transaction):
                return transaction
            else:
                logging.error("Transaction signature verification failed.")
                return None
        except Exception as e:
            logging.error(f"Transaction processing failed: {e}")
            return None

    def verify_signature(self, public_key, transaction):
        data = f"{transaction.crypto_name}{transaction.sender}{transaction.receiver}{transaction.amount}{transaction.fee}".encode('utf-8')
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        try:
            public_key.verify(
                transaction.signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            logging.error(f"Signature verification failed: {e}")
            return False

    def calculate_hash(self, index, previous_hash, timestamp, transactions):
        value = str(index) + str(previous_hash) + str(timestamp) + json.dumps(transactions, default=lambda x: x.__dict__)
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def mine_block(self, sender, receiver, amount, miner_private_key):
        transaction = self.process_transaction(sender, receiver, amount, miner_private_key)
        if transaction:
            if self.current_token_supply + transaction.total_amount <= TOKEN_SUPPLY_LIMIT:
                new_block = self.create_new_block([transaction], transaction)
                self.chain.append(new_block)
                self.current_token_supply += transaction.total_amount
                return new_block
            else:
                logging.error("Transaction exceeds token supply limit.")
        else:
            logging.error("Mining transaction processing failed.")
        return None

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.hash = hash

def main():
    # Generate key pairs for Alice, Bob, and Miner using elliptic curve cryptography
    alice_private_key = ec.generate_private_key(ec.SECP256R1())
    alice_public_key = alice_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    miner_private_key = ec.generate_private_key(ec.SECP256R1())
    miner_public_key = miner_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Create the blockchain and add the genesis block
    blockchain = Blockchain()

    # Alice initiates a transaction with a fee
    block = blockchain.mine_block("Alice", "Bob", 1000000, alice_private_key)
    if block:
        # Print the blockchain, current token supply, and Alice's balance
        logging.info(f"Current Token Supply: {blockchain.current_token_supply}")
        for block in blockchain.chain:
            logging.info(f"Block #{block.index} - Hash: {block.hash}")
            for transaction in block.transactions:
                logging.info(f"  Transaction: {transaction.crypto_name} - {transaction.sender} -> {transaction.receiver}, Amount: {transaction.amount}, Fee: {transaction.fee}")

        alice_balance = blockchain.check_balance("Alice")
        logging.info(f"Alice's Balance: {alice_balance}")

if __name__ == "__main__":
    main()

