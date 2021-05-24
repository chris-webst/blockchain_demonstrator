"""
DEMONSTRATOR:
BLOCKCHAIN AS A MODERN TOOL WITHIN TRADING ELECTRICITY
author: Karolina Podivinska
resources: specified externally

24 May 2021 UPDATE:
Seems like Caroline lost touch with the file with the right offer behavior, so the offers
aren't being removed after someone takes advantage of them or delete them. 
Caroline probably won't be able to fix this up to 12 June 2021; so please excuse this small mistake.
"""
import json
import jsonpickle
import hashlib
import requests
import re
import os
import socket
from datetime import datetime
from datetime import time
from textwrap import dedent
from passlib.hash import pbkdf2_sha256
from flask_sqlalchemy import SQLAlchemy
from flask import render_template
from flask import url_for
from flask import Flask
from flask import request
from flask import redirect
from flask import session
from flask import jsonify
from flask import flash
from Crypto.PublicKey import RSA
from Crypto.Signature import *
from blockchain_5003 import users

class Block:
    def __init__(self, timestamp, pre_hash, trans, index,
                counter=0):
        """
        A function which builds up the block on its own ("constructor").

        :param timestamp: time when the block was created
        :param pre_hash: <str> hash of the previous block
        :param trans: <list> of transactions realized within the block
        :param index: <int> order of the block in the chain
        :param counter <int> counter used in the PoW algoritm
        :param hash: <str> hash of the current block
        """
        self.timestamp = timestamp
        self.pre_hash = pre_hash
        self.trans = trans
        self.index = index
        self.counter = 0
        self.hash = self.compute_hash()

    def compute_hash(self):
        """
        A function which returns the hash of the block contents encoded.
        """
        hash_transactions = ""
        
        for transaction in self.trans:
            hash_transactions += transaction.hash
        
        hash_string = str(self.timestamp) + hash_transactions + self.pre_hash + str(self.counter)
        hash_encoded = json.dumps(hash_string, sort_keys = True).encode();
        return hashlib.sha256(hash_encoded).hexdigest();
    
    def valid_all_trans(self):
        for i in range(0, len(self.trans)):
            transaction = self.trans[i]
            if not transaction.is_valid_trans():
                return False
            return True
    
    def count_proof(self, difficulty):
        """
        The proof of work algorithm.

        :param block: <Block> the block which proof we want to compute
        :return: <str> the proof of the block which fits the criteria
        of leading zeroes
        """
        proof = self.compute_hash()
        while not proof.startswith(difficulty*"0"):
            self.counter += 1
            proof = self.compute_hash()
        return proof

    def valid_proof(self, proof, difficulty):
        """
        A method validating the proof of work
        (proof has the "difficulty" amout of leading zeroes).

        :param block: <Block> block which proof we want to test
        :return: <bool> True if the test is succesfull
        """
        return proof.startswith(difficulty*"0")

class Blockchain:
    def __init__(self):
        """
        A function which builds up the blockchain ("constructor").
        
        :pram chain: <array> chain of the blocks
        :pram unconfirmed: <array> array of the unconfirmed transactions
        :pram difficulty: <int> number of the leading zeroes in the PoW
        :pram fee: <float> fee set for making a transaction
        :pram fee_difference: <float> the raw part of the transaction
        :pram fee_ownership: <array> array of the fees, will be given to miners
        :pram capacity: <int> number of the transactions each block can hold
        :param peers: <set> set of the nodes of the network
        :param trading_data: <array> array of the offers
        :param trading_data: <array> array of the values of the offers
        :param miner_reward: <float> reward for the miner
        """
        self.chain = []  # creates a list of future blocks with the genesis block
        self.unconfirmed = []  # a blank list of unconfirmed trans
        self.difficulty = 4
        """
        the reward for a miner for mining a new block 
        (each person pays 0,00001 % of their transaction) 
        this is stored in the blockchain fee_ownership array
        and then sent to the miner
        """
        self.fee = 0.00001 
        self.fee_difference = 1 - self.fee
        self.fee_ownership = []  
        
        self.capacity = 5
        self.peers = set()
        
        self.genesis()
        
        self.trading_data = []
        self.trading_storage = []
        
        self.miner_reward = 0.42

    def genesis(self):
        """
        A function which creates genesis block.

        It sets timestamp to actual time, previous hash is set to "0",
        assigns a blank list of transactions and sets index to 0.
        Then the hash of all contents of genesis block is computed.
        """
        genesis_block = Block(datetime.now().strftime("%d/%m/%Y, %H:%M:%S"), "0", [], 0)
        proof = genesis_block.count_proof(self.difficulty)
        if genesis_block.valid_proof(proof, self.difficulty):
            self.chain.append(genesis_block)

    def chain_json_encode(self):
        result = []
        for block in self.chain:
            block_json = {}
            block_json['timestamp'] = block.timestamp
            block_json['pre_hash'] = block.pre_hash
            block_json['index'] = block.index
            block_json['counter'] = block.counter
            block_json['hash'] = block.hash
          
            transaction_json = []
            for trans in block.trans:
                trans_json = {}
                trans_json['sender'] = trans.sender
                trans_json['receiver'] = trans.receiver
                trans_json['amount'] = trans.amount
                trans_json['timestamp'] = trans.timestamp
                trans_json['hash'] = trans.hash
                transaction_json.append(trans_json) 
     
            block_json['trans'] = transaction_json
            result.append(block_json)

        return result
    
    def trans_json_encode(self):
        result = []
        for trans in self.unconfirmed:
            trans_json = {}
            trans_json['timestamp'] = trans.timestamp
            trans_json['sender'] = trans.sender
            trans_json['receiver'] = trans.receiver
            trans_json['amount'] = trans.amount
            trans_json['hash'] = trans.hash
            result.append(trans_json)
        return result
    
    def offer_json_encode(self):
        result = []
        for offer in self.trading_data:
            if type(offer) != int :
                print(offer)
                offer_json = {}
                offer_json['retailer'] = offer.retailer
                offer_json['sell_this'] = offer.sell_this
                offer_json['for_this'] = offer.for_this
                result.append(offer_json)
            else:
                result.append(0)
        return result

    def storage_json_encode(self):
        result = []
        for storage in self.trading_storage:
            storage_json = {}
            storage_json['storage'] = storage
            result.append(storage_json)
        return result
            
    def storage_json_decode(self, storage):
        chain = []
        for json in storage:
            stor = json["storage"]
            chain.append(stor)
        return chain
            
    def chain_json_decode(self, json):
        chain = []
        for block_json in json:
            
            trans = []
            for trans_json in block_json['trans']:
                transaction = Transaction(trans_json['sender'], 
                                          trans_json['receiver'], 
                                          trans_json['amount'])
                transaction.timestamp = trans_json['timestamp']
                transaction.hash = trans_json['hash']
                trans.append(transaction)
        
            block = Block(block_json['timestamp'], block_json["pre_hash"], 
                          trans, block_json['index'])
            block.hash = block_json["hash"]
            block.counter = block_json["counter"]
            chain.append(block)
                
        return chain
    
    def trans_json_decode(self, trans):
        chain = []
        for json in trans:
            
            transaction = Transaction(json['sender'], 
                                          json['receiver'], 
                                          json['amount'])
            transaction.timestamp = json['timestamp']
            transaction.hash = json['hash']
            chain.append(transaction)
        return chain
    
    def offer_json_decode(self, offer):
        chain = []
        for json in offer:
            if type(json) != int: 
                offer = Offer(json['retailer'], 
                          json['sell_this'], 
                          json['for_this'])
                chain.append(offer)
            else:
                chain.append(offer)
        return chain

    def mine_unconfirmed(self, miner):
        if len(self.unconfirmed)< 1:
            flash("No pending transactions to mine")
            return redirect("/pending_tx")
        elif len(self.unconfirmed) < self.capacity:
            flash("Not enough transactions to mine")
            return redirect("/pending_tx")
        else:
            new_t = []
            for num in range(self.capacity):
                new_t.append(self.unconfirmed[0])
                self.unconfirmed.remove(self.unconfirmed[0])
            new_block = Block(datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
                                  self.chain[-1].compute_hash(),
                                  new_t,
                                  self.chain[-1].index + 1)
            new_block.counter = 0
            new_block.hash = new_block.count_proof(self.difficulty)
            if new_block.valid_proof(new_block.hash, self.difficulty):
                self.chain.append(new_block)
                
                reward = self.miner_reward
                # the amount of the miner reward
                if len(self.fee_ownership) >= 5:
                    for i in range(self.capacity):
                        reward += float(self.fee_ownership[0])
                        self.fee_ownership.remove(self.fee_ownership[0])
                pay_miner = Transaction("Reward For The Miner",
                                        miner.username + "_electricity", reward)
                miner.electricity_balance += reward
                db.session.commit()
                self.fee_ownership.append(0)
                self.unconfirmed.append(pay_miner)
                return redirect("/pending_tx")
            else:
                flash("A bug occured")
                return redirect("/pending_tx")

    def check_chain_validity(self):
        for node in range(1, len(self.chain)):
            block_comparer = self.chain[node-1]
            block = self.chain[node]
            
            if not block.valid_all_trans():
                return False
            
            if block.compute_hash() != block.hash:
                return False
            
            if block.pre_hash != block_comparer.hash:
                return False
        
        return True

    def generate_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out =  open("private.pem", "wb")
        file_out.write(private_key)
    
        public_key = key.publickey().export_key()
        file_out = open("receiver.pem", "wb")
        file_out.write(public_key)

        return key.publickey().export_key().decode("ASCII")


    def add_trans(self, sender, receiver, amount, key_string, sender_key):
        byte_key = key_string.encode("ASCII")
        byte_sender_key = sender_key.encode("ASCII")
        
        key = RSA.import_key(byte_key)
        sender_key_key = RSA.import_key(byte_sender_key)
        
        if not sender or not receiver or not amount:
            return False

        else:
            amount_sent = float(amount)*self.fee_difference
            self.fee_ownership.append(float(amount)*self.fee)
        
            transaction = Transaction(sender, receiver, amount_sent)
            transaction.sign(key, sender_key_key)
        
            if not transaction.valid_transaction():
                return False
            
            else:
                self.unconfirmed.append(transaction)
                return True


class Transaction:
    def __init__(self, sender, receiver, amount):
        """
        A function creating a new transaction.
        
        :param sender: <str> sender of the transaction
        :param receiver: <str> receiver of the transaction
        :param amount: <float> amount of the commodity within the transaction
        :param time: <time> current time
        """
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = datetime.now().strftime("%d/%m/%Y, %H:%M:%S")
        self.hash = self.compute_transaction_hash()
        self.signature = 0

    def compute_transaction_hash(self):
        """
        A function which returns the hash of the transaction contents encoded.
        """
        hash_string = (self.sender + self.receiver + str(self.amount) + str(self.timestamp))
        hash_encoded = json.dumps(hash_string, sort_keys=True).encode()
        return hashlib.sha256(hash_encoded).hexdigest()

    def valid_transaction(self):
        if (self.hash != self.compute_transaction_hash()):
            return False
        if self.sender == self.receiver:
            return False
        if self.sender == "Reward For The Miner":
            return True
        if not self.signature or len(self.signature) == 0:
            return False
        return True

    def sign(self, key, sender_key):
        if (self.hash != self.compute_transaction_hash()):
            return False
        if(str(key.publickey().export_key()) != str(sender_key.publickey().export_key())):
            return False
        pkcs1_15.new(key)
        self.signature = "done"
        return True


class Offer():
    def __init__(self, retailer, sell_this, for_this):
        self.retailer = retailer
        self.sell_this = sell_this
        self.for_this = for_this

app = Flask(__name__, static_url_path="/templates", static_folder="templates/")
b = Blockchain()
db = SQLAlchemy(app)
app.secret_key = pbkdf2_sha256.hash("my_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.carolinesbdemonstrator.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

def consensus():
    addresses = ["127.0.0.1:5003"]
    for node in addresses:
        b.peers.add(node)
        return True
  
@app.route("/carolines_blockchain")
def blockchain():
    consensus()
    new_chain = None
    max_length = len(b.chain)
    for node in b.peers:
        response = requests.get(f"http://{node}/chainome")

        if response.status_code == 200:
            length = response.json()['length']
            chain = response.json()['chain']

            if length > max_length and b.check_chain_validity():
                max_length = length
                new_chain = chain
    
        if new_chain:
            b.chain = b.chain_json_decode(new_chain)
            b.unconfirmed = []
            print("New chain")
    return render_template("chain.html", b = b)  
       
@app.route("/", methods = ["GET", "POST"])
def view():
    return render_template("index.html", usr="5004")

@app.route("/login", methods = ["GET", "POST"])
def login():
    if "user" in session:
        return redirect("/view_profile")
    elif request.method == "POST":
        user = request.form.get("username")
        password = request.form.get("password")
        user_object = users.query.filter_by(username = user).first()
        if user_object is None:
            flash("This user does not exist. Fix the username or \
                create a new account.")
            return redirect("/login")
        else:
            if pbkdf2_sha256.verify(password, user_object.password):
                session["user"] = user
                return redirect("/view_profile")
            else:
                flash("You have entered a wrong password. Try again.")
                return redirect("/login")
    else:
        return render_template("login.html")
 
@app.route("/logout", methods = ["GET", "POST"])
def logout():
    if "user" in session:
        flash(str(session["user"]+" was successfully logged out."))
        session.pop("user", None)
    return redirect("/login")

@app.route("/chainome")
def get_chain():
    response = {
        'chain': b.chain_json_encode(),
        'length': len(b.chain)
    }
    return jsonify(response), 200


@app.route("/pending")
def pending():
    content = b.unconfirmed
    if len(content) < 1:
        content = ["no pending transactions"]
        response = {
            'chain': b.trans_json_encode(),
            'length': 0
        }
    else:
        response = {
            'chain': b.trans_json_encode(),
            'length': len(content)
        }
    return jsonify(response), 200

@app.route("/pending_tx", methods=["GET", "POST"])
def get_pending_tx():
    if request.method=="GET":
        consensus()
        new_pending = None
        max_length = len(b.unconfirmed)
        for node in b.peers:
            response = requests.get(f"http://{node}/pending")

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length:
                    max_length = length
                    new_pending = chain
    
            if new_pending:
                b.unconfirmed = b.trans_json_decode(new_pending)
                
        content = b.unconfirmed
        if len(content) < 1:
            content = ["no pending transactions"]
        else:
            content = []
            for transaction in b.unconfirmed:
                content.append(transaction.sender + " is sending " +
                            str(transaction.amount) + " coins to " + transaction.receiver)
        return render_template("pending.html", content = content)
    else:
        mine()
        return redirect("/pending_tx")

def mine():
    if "user" in session:
        content = b.unconfirmed
        if len(content) < 1:
            content = ["no pending transactions"]
            return render_template("pending.html", content = content)
        else:
            content = []
            for transaction in b.unconfirmed:
                content.append(transaction.sender + " is sending " +
                               str(transaction.amount) + " coins to " + transaction.receiver)
            miner = users.query.filter_by(username = str(session["user"])).first()
            if request.method == "POST":
                return(b.mine_unconfirmed(miner))
            else:
                return render_template("pending.html", content = content)
    else:
        return redirect("/login")

@app.route("/new_account", methods=["GET", "POST"])
def new_account():
    if request.method == "POST":
        new_user = request.form.get("username")
        new_user_psw = request.form.get("password")
        new_user_psw_conf = request.form.get("confirm_password")
        # hashes new user's password to store it in a secure way
        secure_psw = pbkdf2_sha256.hash(new_user_psw)
        if double_user(new_user) is True:
            if my_secure_psw(new_user_psw) is True:
                if same_password(new_user_psw, new_user_psw_conf) is True:
                    key = b.generate_keys()
                    newbie = users(new_user, secure_psw, 1000, 10, key)
                    db.session.add(newbie)  # adds the new user to the database
                    db.session.commit()  # confirms the action
                    flash("Succesfully registered!")
                    return redirect("/view_profile")
                else:
                   return render_template('newbie.html')
            else:
                return render_template('newbie.html')
        else:
            return render_template('newbie.html') 
    else:
        return render_template('newbie.html')

@app.route("/view_profile")
def view_profile():
    if "user" in session:
        # finds the user which is in session in the user database
        offers = []
        user = users.query.filter_by(username=str(session["user"])).first()
        counter = 0
        for offer in b.trading_data:
            if type(offer) == Offer:
                if offer.retailer == user.username:
                    offers.append(str(counter) + ". " + str(offer.retailer) +
                               " offers to sell " + str(offer.sell_this) + 
                               " electricity coins for " + str(offer.for_this) +
                                   " money coins")
            counter += 1
        if len(offers) == 0:
            offers = ["You have no offers"]
        return render_template("profile.html", content=[user.username, 
        user.password, user.money_balance, user.electricity_balance, user.key, offers])
    else:
        return redirect("/login")

@ app.route('/new_transaction', methods = ["POST", "GET"])
def new_transaction():
    if "user" in session:
        if request.method == 'POST':
            sender = users.query.filter_by(username = str(session["user"])).first()
            receiver = users.query.filter_by(username = str(request.form["to"])).first()
            amount = request.form["how_much"]
            which_one = request.form["commodity"]
            key = sender.key
            if receiver_confirmation(sender, receiver) is True:
                if str(which_one) == "money":
                    if check_money(amount, float(sender.money_balance)) is True:
                        b.add_trans(str(sender.username)+"_money", str(receiver.username)+"_money", 
                                    amount, key, key)
                        sender.money_balance -= float(amount)
                        receiver.money_balance += float(amount)*float(b.fee_difference)
                        db.session.commit()
                        flash("Your transaction has been submitted!")
                        return redirect(url_for("get_pending_tx"))
                    else:
                        return redirect("/new_transaction")
                else:
                    if check_money(amount, float(sender.money_balance)) is True:
                        your_t = b.add_trans(str(sender.username)+"_electricity", str(receiver.username)+"_electricity", 
                                            amount, key, key)
                        sender.electricity_balance -= float(amount)
                        receiver.electricity_balance += float(amount)*float(b.fee_difference)
                        db.session.commit()
                        flash("Your transaction has been submitted!")
                        return redirect(url_for("get_pending_tx"))
                    else:
                        return redirect("/new_transaction")
            else:
                return redirect("/new_transaction")
        else:
            return render_template("transaction.html")
    else:
        return redirect("/login")


@ app.route("/buy_electricity", methods = ["POST", "GET"])
def buy_electricity():
    consensus()
    new_offers = None
    new_storage = None
    max_length = len(b.trading_data)
    for node in b.peers:
        response = requests.get(f"http://{node}/buy")

        if response.status_code == 200:
            length = response.json()['length']
            chain = response.json()['chain']
            storage = response.json()['storage']

            counter = 0
            for offer in chain:
                if max_length != 0:
                    if type(offer) != Offer:
                        max_length = length
                        new_offers = chain
                        new_storage = storage
                        break
                    elif offer != b.trading_data[counter]:
                        max_length = length
                        new_offers = chain
                        new_storage = storage
                    elif len(chain) > max_length:
                        max_length = length
                        new_offers = chain
                        new_storage = storage
                        break
                    else:
                        counter += 1
                else:
                    max_length = length
                    new_offers = chain
                    new_storage = storage
                    break

        if new_offers:
            b.trading_data = b.offer_json_decode(new_offers)
            b.trading_storage = b.storage_json_decode(new_storage)
            
    content = []
    count_me = 0
    for offer in b.trading_data:
        if type(offer) == Offer:
            content.append(str(count_me) +". " + offer.retailer + " offers to sell " +
                            str(offer.sell_this) + " electricity coins for " + str(offer.for_this) +
                            " money coins")
        count_me += 1
    if count_me == 0:
        flash("There are no available offers.")
        return render_template("buy.html", content=[])
    if request.method == "POST":
            return redirect("/purchase")
    else:
        return render_template("buy.html", content = content)
    
@app.route("/buy")
def buy():
    content = b.trading_data
    response = {
            'chain': b.offer_json_encode(),
            'length': len(content),
            'storage': b.storage_json_encode()
        }
    return jsonify(response), 200

@ app.route("/purchase", methods = ["POST", "GET"])
def purchase():
    if "user" in session:
        if request.method == "POST":
            num = int(request.form.get("offer_num"))
            if (num >= len(b.trading_data)) or (type(b.trading_data[num]) != Offer):
                flash("There is no offer with number " + str(num))
                return redirect("/purchase")
            else:
                retailer = users.query.filter_by(username = str(b.trading_data[num].retailer)).first()
                you = users.query.filter_by(username = str(session["user"])).first()
                el = b.trading_data[num].sell_this
                mon = b.trading_data[num].for_this
                if retailer.username != you.username:
                    if check_money(mon, float(you.money_balance)) is True:
                        b.add_trans(retailer.username + "_electricity", you.username + "_electricity", 
                                    el, retailer.key, retailer.key)
                        you.electricity_balance += float(b.trading_storage[num])*float(b.fee_difference)
                        b.trading_storage[num] = 0
                        b.add_trans(you.username + "_money", retailer.username + "_money", 
                                    mon, you.key, you.key) 
                        you.money_balance -= float(mon)
                        retailer.money_balance += float(mon)*float(b.fee_difference)
                        b.trading_data[num] = 0
                        db.session.commit()
                        flash("Your purchase has been submitted!")
                        return redirect(url_for("get_pending_tx"))
                    else:
                        flash("You do not have this amount of money. Your money balance \
                        is "+str(you.money_balance)+" coins.")
                        return redirect("/purchase")
                else:
                    flash("You have made this offer, so you cannot make a purchase. If you want to \
                        delete the purchase, go to your account and click 'delete purchase'.")
                    return redirect("purchase")
        else:
            return render_template("which.html")
    else:
        return redirect("/login")
    
@ app.route("/sell_electricity", methods = ["POST", "GET"])
def sell():
    if "user" in session:
        if request.method == "POST":
            retailer = users.query.filter_by(username = str(session["user"])).first()
            electricity = request.form.get("how_much")
            money = request.form.get("how_much_receive")
            if check_money(float(electricity), retailer.electricity_balance) is True:
                offer = Offer(retailer.username, electricity, money)
                b.trading_data.append(offer)
                print(b.trading_data)
                b.trading_storage.append(float(electricity))
                retailer.electricity_balance -= float(electricity)
                db.session.commit()
                return redirect("/buy_electricity")
            else:
                return redirect("/sell_electricity")
        else:
            return render_template("sell.html")
    else:
        return redirect("/login")

@ app.route("/delete_offer", methods = ["POST", "GET"])
def delete():
    if "user" in session:
        if request.method == "POST":
            retailer = users.query.filter_by(username = str(session["user"])).first()
            offer_num = request.form.get("offer_num")
            if (int(offer_num) >= len(b.trading_data)) or (type(b.trading_data[int(offer_num)]) != Offer):
                flash("There is no offer with number " + str(offer_num))
                return redirect("/delete_offer")
            if str(session["user"]) != b.trading_data[int(offer_num)].retailer:
                flash("This is not your offer, you cannot delete it.")
                return redirect("/delete_offer")
            else:
                b.trading_data[int(offer_num)] = 0
                retailer.electricity_balance += b.trading_storage[int(offer_num)]
                b.trading_storage[int(offer_num)] = 0
                db.session.commit()
                flash("your offer has been deleted.")
                return redirect("/view_profile")
        else:
            return render_template("delete.html")
    else:
        return redirect("/login")
        
def my_secure_psw(pasw):
    if not re.search("[a-z]", pasw):
        flash("Your password has to contain at least one \
                lower-case letter!")
        return False
    elif not re.search("[A-Z]", pasw):
        flash("Your password has to contain at least one \
            upper-case letter!")
        return False
    elif not re.search("[0-9]", pasw):
        flash("Your password has to contain at least one cipher!")
        return False
    elif len(pasw) < 12:
        flash("Your password has to be at least 12 chars long!")
        return False
    else:
        return True

def double_user(user):
    found_user = users.query.filter_by(username=user).first()
    if found_user:
        flash("User already exists! Choose a different username.")
        return False
    elif user == "Reward For The Miner":
        flash("You can not use this username. \
        It is used for miner rewards. Choose a different one.")
        return False
    else:
        return True

def same_password(psw, psw_2):
    if psw != psw_2:
        flash("The passwords do not match!")
        return False
    else:
        return True
    
def receiver_confirmation(sender, receiver):
    if receiver is None:
        flash("This user does not exist. Fix the name \
            of the receiver and then try again.")
        return False
    elif sender == receiver:
        flash("Sorry, but you can't send coins to yourself.")
        return False
    else:
        return True
    
def check_money(amount, person):
    if float(amount) > person:
        flash("You do not have this amount of coins. Your money balance \
            is "+str(person)+" coins.")
        return False
    else:
        return True

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, port = 5004)
