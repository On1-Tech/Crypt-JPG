import random, base64, sys, hashlib
from PIL import Image
from Cryptodome.Cipher import AES
from functools import reduce

#Class that handles operations with message include: padding, converting string to bits, and parsing encrypted string. 
#Instance variables are:  message - message itself, block - cipher block size, len - length of message, vlen - length of vector, 
#password - password used for encyption/decription(hashed), messages - list with message itself, length and vector, v - vektor, 
#crypt - instance of AES, crypted_strings - list with crypted messages(vector not crypted), full_length - length of message with padding.
class Message:

#If there is no password then "Example" will used as password. 
	def __init__(self,message='',password='Example'):
		self.message=message
		self.block=32
		self.vlen=16
		self.len=len(message)
		self.password=hashlib.sha256(password.encode('utf-8')).digest() #hashing password
		if self.len == 0: self.messages=['', '0;'] #if message is empty
		else: self.messages=[message, str(self.len)+';'] #otherwise

#Creation of vector and addition of padding to messages (message itself, length)
	def prepare(self):
		self.v=''
		for num in range(0, self.vlen): self.v += chr(random.randint(32,127))   
		for num in (0,1):
			if len(self.messages[num]) % self.block != 0:
				for x in range(len(self.messages[num]) % self.block, self.block): self.messages[num] += chr(random.randint(32,127))		   
		self.messages.append(self.v)
		self.v=bytes(self.v, encoding="UTF-8")

#Coverting full message to bits(bits represented as normal string)
	def encrypt(self):
		self.prepare()
		messages = []
		#changing encoding to UTF-8(because AES working only with it) and encrypting messages.
		for num in (0,1):
			messages.append(bytes(self.messages[num], encoding="UTF-8"))
			try:
				self.__crypt = AES.new(self.password, AES.MODE_CBC, self.v)
				messages[num] = self.__crypt.encrypt(messages[num])
			except:	exit_message("Something went wrong with encrypting strings.")
		messages.append(self.v) #adding vektor as 3rd element of list
		self.crypted_strings =[]
		#representing encrypted message as binary in string format.
		for current_string in messages:	self.crypted_strings.append(''.join(map(lambda x: bin(x)[2:].zfill(8), current_string)))
			
#Parsing lenght and fullmessage from received string (used for encryption)
	def decrypt(self,strings):
		self.v=strings[2][:self.vlen] #cutting extras for string[1] and v
		strings[1] = strings[1][:self.block]
		self.messages=[] #voiding since we are getting new self.messages after encoding
		#decryption
		try:
			for current_string in strings[:-1]:
				self.__crypt = AES.new(self.password, AES.MODE_CBC, self.v)
				self.messages.append(self.__crypt.decrypt(current_string).decode())
		except: exit_message("Something went wrong with decrypting string. Most probably it was your password.")
		self.len = int(self.messages[1].split(';',1)[0]) #parsing len
	
#Full lenght of message including padding.
	def get_full_lenght(self):
		self.full_lenght = (self.len//self.block+1)*self.block*8

	def __str__(self):
		if self.message!='':
			return f"Message - {self.message}\nFull Message - {self.messages[0]}\nMessage Length - {self.len}\nBinary version({len(self.crypted_strings[0])} bits) - {self.crypted_strings[0]}"
		else:
			return f"Message - {self.messages[0][:self.len]}\nFull Message - {self.messages[0]}\nMessage Length - {self.len}"

	def __repr__(self):
		return f"{self.message}"

#Class that handles Picture operations. Includes: Loading and saving image, getting and setting least significant bit(LSB) in 1byte integer, 
#getting and setting least significant bits of particular pixel, spiral walk performing different operations over pixels in picture.
#Instance variables: filename - filename of picture, x,y - size of picture, pix - picture object, im - image file.
class Pictures:

	def __init__(self, filename):
		self.name=filename

#Loading picture and figuring out size.
	def load_picture (self):
		try:
			self.im = Image.open(self.name)
			self.pix = self.im.load()
			self.x,self.y=self.im.size
		except:	exit_message("Something went wrong with opening picture.")

#Saving picture as PNG file.
	def save_picture (self):
		try: self.im.save(self.name.rsplit('.',1)[0]+'.png',"PNG")
		except: exit_message("Something went wrong with saving picture.")

#Replacing of LSB in integer(num).
	def __add_bit(self, num, bit):
		if bit==' ': bit='0'
		return (int('0b'+bin(num)[2:].zfill(8)[:-1]+bit, 2))

#Getting LSB from integer(num).
	def __get_bit(self,num):
		return (bin(num)[-1:])

#Getting colour of pixel with x,y coordinates.
	def get_colour(self, x, y):
		try: return(self.pix[x,y])
		except: exit_message("Something wrong with picture file. It must be PNG.")

#Setting colour of pixel with x,y coordinates.
	def set_colour(self, x, y, r, g, b):
		try: self.pix[x,y]= (r,g,b)
		except:	exit_message("Something wrong with picture file. It must be jpg in RGB.")

#Adding new value to colours LSB of pixel (with x,y coordinates). It is called from spiral_walk method so it have some extra parameters, because
#all methods called by spiral_walk suppoused to take and return same arguments. Count - accumulator that decreasing after every call of this 
#method, colour_bits arrays of 3 character that includes new LSBs, and stored_data is not im use.
	def adding_bits(self,x,y,counter,colour_bits,stored_data):
		try:
			if counter >= 0:
				r,g,b=self.get_colour(x,y)
				try: newr = self.__add_bit(r,colour_bits[0])
				except: newr = r
				try: newg = self.__add_bit(g,colour_bits[1])
				except: newg = g
				try: newb = self.__add_bit(b,colour_bits[2])
				except: newb = b
				self.set_colour(x,y,newr,newg,newb)
				counter -=1
		except:	exit_message("Something wrong with picture file. It must be jpg in RGB.")
		return ('', counter)

#Getting value of pixel(with x,y coordinates) colours LSB. Normally it is executed from spiral_walk method. Count - accumulator that decreasing 
#after every call of this method, colour_bits array of characters that includes new LSBs (basicly 0 or 1), and stored_data is string with bits. 
#Returns accumulator and list of strings with just added bits.
	def getting_bits(self,x,y,counter,colour_bits,stored_data):
		try:
			if counter >= 0: 
				stored_data=[x+str(self.__get_bit(y)) for x,y in zip(stored_data,self.get_colour(x,y))]
				counter -= 1
		except:	exit_message("Something wrong with picture file. It must be PNG.")
		return (stored_data, counter)

#Decoding strings of bits to normal ones. 
	def decoding_bits(self, bin_strings):
		return ([bytes([int(('0b'+s[i:i+8]), 2) for i in range (0, len(s), 8)]) for s in bin_strings])

#Calling spiral_walk with method for adding message. bin_strings is message in binary form.
	def spiral_set_message(self, bin_strings):
		if self.x*self.y>len(bin_strings):
			self.spiral_walk(0, len(bin_strings[0]), [s.ljust(len(bin_strings[0]),' ') for s in bin_strings], ' ', self.adding_bits)
		else: exit_message("Message is too long for your picture.")

#Calling of spiral_walk method for getting message, full_lenght - is message lenght, that suppoused to be obtained.
	def spiral_get_message(self, full_lenght):
		if self.x*self.y>full_lenght:
			return (self.decoding_bits(self.spiral_walk(0, full_lenght-1, [' '.zfill(full_lenght)]*3, ['']*3, self.getting_bits)))
		else: exit_message("File corrupted.")

#Basically previous method for 1 block of text(cipher block size). It is enough to find out real lenght of message.
	def spiral_get_len(self, block):
		return(self.spiral_get_message(block*8))

#Main method that make most of work. It moving over picture pixels in spiral order and perform some operation(getting_bits or adding_bits)
#recursively. Movement made with 4 for cycles. Parametrs: step_number - always 0 at start, bin_strings - strings that represent message in 
#binary way (or empty in case of getting_bits), stored_data - bits from picture in case of getting_bits, and method - function that performed.
	def spiral_walk(self,step_number,counter,bin_strings,stored_data,method):
		#forming list with bits for every colour (r,g,b)
		def c_binstring():
			return([cbinstring[-counter] for cbinstring in bin_strings])

		if self.x//2>=step_number & self.y//2>=step_number & counter>-1:
			for i in range(step_number,self.x-step_number): stored_data, counter=method(step_number,i,counter,c_binstring(),stored_data)
			if not self.x>self.y & self.y%2==0 & self.y//2==step_number:
				for i in range(step_number,self.y-step_number): stored_data, counter=method(i,self.x-step_number,counter,c_binstring(),stored_data)
				for i in range(self.x-step_number,step_number,-1): stored_data, counter=method(self.y-step_number,i,counter,c_binstring(),stored_data)
				if not self.x<self.y & self.x%2==0 & self.x//2==step_number:
					for i in range(self.y-step_number,step_number,-1): stored_data, counter=method(i,step_number,counter,c_binstring(),stored_data)
			step_number +=1
			stored_data=self.spiral_walk(step_number,counter,bin_strings,stored_data,method)

		elif self.x%2==0 | self.y%2==0:
			if self.x==self.y: stored_data, counter=method(step_number,step_number,counter,c_binstring(),stored_data)
			if self.x<self.y & self.x%2==0: stored_data, counter=method(self.y-step_number+1,step_number-1,counter,c_binstring(),stored_data)
			if self.x>self.y & self.y%2==0: stored_data, counter=method(step_number-1,self.x-step_number+1,counter,c_binstring(),stored_data)
		return (stored_data)

	def __repr__(self):
		return f"{self.name}"

	def __str__(self):
		return f"{self.name}"

#Childclass for Pictures that include Message. Everything is pretty simple, so probably no extra comments needed
class Picture_with_Message(Pictures):
	def __init__(self,filename,message='',password='Example'):
		Pictures.__init__(self,filename)
		self.crypted_message=Message(message,password)

	def get_message(self):
		Pictures.load_picture(self)
		self.crypted_message.decrypt(Pictures.spiral_get_len(self,self.crypted_message.block))
		self.crypted_message.get_full_lenght()
		self.crypted_message.decrypt(Pictures.spiral_get_message(self,self.crypted_message.full_lenght))

	def set_message(self):
		self.crypted_message.encrypt()
		Pictures.load_picture(self)
		Pictures.spiral_set_message(self,self.crypted_message.crypted_strings)
		Pictures.save_picture(self)

	def __repr__(self):
		return f"Picture - {Pictures.__str__(self)}\n{self.crypted_message}"

	def __str__(self):
		return f"Picture - '{Pictures.__str__(self)}\n{self.crypted_message}"

def exit_message(message):
	if len(message)!=0: message +="\n"
	sys.exit(message+"""Command line syntax: 
to crypt crypt.py add [file] [text] [password] 
to encrypt crypt.py get [file] [password]""")

if len(sys.argv) < 3: exit_message("")

if sys.argv[1] == "get":
	p=Picture_with_Message(sys.argv[2],'',sys.argv[3])
	p.get_message()
	print(p)

if sys.argv[1] == "add":
	p=Picture_with_Message(sys.argv[2],sys.argv[3],sys.argv[4])
	p.set_message()
	print (str(p)+'\nMessage added to picture.')