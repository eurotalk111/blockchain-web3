import hashlib
import time
import json
from uuid import uuid4
from flask import Flask, jsonify, request
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class Wallet:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
        self.address = self.generate_address()
    
    def generate_address(self):
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_bytes).hexdigest()[:40]
    
    def sign_transaction(self, transaction):
        signature = self.private_key.sign(
            json.dumps(transaction, sort_keys=True).encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()
    
    @staticmethod
    def verify_signature(public_key, transaction, signature):
        try:
            public_key.verify(
                bytes.fromhex(signature),
                json.dumps(transaction, sort_keys=True).encode(),
                ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

class Transaction:
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = time.time()
        self.transaction_id = str(uuid4()).replace('-', '')
        self.signature = None
    
    def to_dict(self):
        return {
            'transaction_id': self.transaction_id,
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'signature': self.signature
        }
    
    def sign(self, wallet):
        if wallet.address != self.sender:
            raise ValueError("You can only sign your own transactions!")
        self.signature = wallet.sign_transaction(self.to_dict())
    
    def is_valid(self):
        if self.sender == "MINING_REWARD":
            return True
        
        if not self.signature:
            return False
        
        # In a real implementation, we'd look up the public key from the sender address
        # For simplicity, we'll assume we have access to all wallets here
        sender_wallet = next((w for w in node.wallets if w.address == self.sender), None)
        if not sender_wallet:
            return False
        
        return Wallet.verify_signature(
            sender_wallet.public_key,
            self.to_dict(),
            self.signature)

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def mine_block(self, difficulty):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 4
        self.pending_transactions = []
        self.mining_reward = 10
        self.nodes = set()
        self.wallets = []
    
    def create_genesis_block(self):
        return Block(0, time.time(), [], "0")
    
    def get_last_block(self):
        return self.chain[-1]
    
    def mine_pending_transactions(self, mining_reward_address):
        reward_tx = Transaction("MINING_REWARD", mining_reward_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)
        
        block = Block(
            len(self.chain),
            time.time(),
            self.pending_transactions,
            self.get_last_block().hash)
        
        block.mine_block(self.difficulty)
        print(f"Block mined: {block.hash}")
        self.chain.append(block)
        
        self.pending_transactions = []
    
    def add_transaction(self, transaction):
        if not transaction.is_valid():
            raise ValueError("Invalid transaction!")
        
        if transaction.sender != "MINING_REWARD":
            sender_balance = self.get_balance(transaction.sender)
            if sender_balance < transaction.amount:
                raise ValueError("Insufficient balance!")
        
        self.pending_transactions.append(transaction)
        return self.get_last_block().index + 1
    
    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address:
                    balance -= tx.amount
                if tx.recipient == address:
                    balance += tx.amount
        return balance
    
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            if current.hash != current.calculate_hash():
                return False
            
            if current.previous_hash != previous.hash:
                return False
            
            if current.hash[:self.difficulty] != "0" * self.difficulty:
                return False
            
            for tx in current.transactions:
                if not tx.is_valid():
                    return False
        
        return True
    
    def add_node(self, address):
        self.nodes.add(address)
    
    def resolve_conflicts(self):
        longest_chain = None
        max_length = len(self.chain)
        
        for node_address in self.nodes:
            try:
                response = requests.get(f'http://{node_address}/chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    
                    if length > max_length and self.validate_chain(chain):
                        max_length = length
                        longest_chain = chain
            except requests.exceptions.RequestException:
                continue
        
        if longest_chain:
            self.chain = self.chain_from_json(longest_chain)
            return True
        
        return False
    
    @staticmethod
    def validate_chain(chain):
        temp_chain = []
        for block_data in chain:
            transactions = []
            for tx_data in block_data['transactions']:
                tx = Transaction(
                    tx_data['sender'],
                    tx_data['recipient'],
                    tx_data['amount'])
                tx.timestamp = tx_data['timestamp']
                tx.transaction_id = tx_data['transaction_id']
                tx.signature = tx_data['signature']
                transactions.append(tx)
            
            block = Block(
                block_data['index'],
                block_data['timestamp'],
                transactions,
                block_data['previous_hash'],
                block_data['nonce'])
            block.hash = block_data['hash']
            temp_chain.append(block)
        
        # Validate the temporary chain
        for i in range(1, len(temp_chain)):
            current = temp_chain[i]
            previous = temp_chain[i-1]
            
            if current.hash != current.calculate_hash():
                return False
            
            if current.previous_hash != previous.hash:
                return False
            
            for tx in current.transactions:
                if not tx.is_valid():
                    return False
        
        return True
    
    @staticmethod
    def chain_from_json(chain_json):
        chain = []
        for block_data in chain_json:
            transactions = []
            for tx_data in block_data['transactions']:
                tx = Transaction(
                    tx_data['sender'],
                    tx_data['recipient'],
                    tx_data['amount'])
                tx.timestamp = tx_data['timestamp']
                tx.transaction_id = tx_data['transaction_id']
                tx.signature = tx_data['signature']
                transactions.append(tx)
            
            block = Block(
                block_data['index'],
                block_data['timestamp'],
                transactions,
                block_data['previous_hash'],
                block_data['nonce'])
            block.hash = block_data['hash']
            chain.append(block)
        return chain

# Initialize Flask app
app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')
node = Blockchain()

@app.route('/mine', methods=['GET'])
def mine():
    if not node.wallets:
        return jsonify({'message': 'No wallets available'}), 400
    
    miner_wallet = node.wallets[0]
    node.mine_pending_transactions(miner_wallet.address)
    
    response = {
        'message': "New block mined",
        'index': node.get_last_block().index,
        'hash': node.get_last_block().hash,
        'transactions': [tx.to_dict() for tx in node.get_last_block().transactions]
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature']
    
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400
    
    transaction = Transaction(values['sender'], values['recipient'], values['amount'])
    transaction.signature = values['signature']
    
    try:
        index = node.add_transaction(transaction)
        response = {'message': f'Transaction will be added to Block {index}'}
        return jsonify(response), 201
    except ValueError as e:
        return jsonify({'message': str(e)}), 400

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': [block.__dict__ for block in node.chain],
        'length': len(node.chain)
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    
    if nodes is None:
        return jsonify({'message': 'Error: Please supply a valid list of nodes'}), 400
    
    for node_address in nodes:
        node.add_node(node_address)
    
    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(node.nodes)
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = node.resolve_conflicts()
    
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': [block.__dict__ for block in node.chain]
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': [block.__dict__ for block in node.chain]
        }
    
    return jsonify(response), 200

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    wallet = Wallet()
    node.wallets.append(wallet)
    
    response = {
        'private_key': wallet.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()).decode(),
        'public_key': wallet.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        'address': wallet.address
    }
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser
    
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    
    app.run(host='0.0.0.0', port=port)