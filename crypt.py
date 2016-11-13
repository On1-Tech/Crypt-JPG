import random, base64, sys, hashlib
from PIL import Image
from Crypto.Cipher import AES
from functools import reduce

#Class for basic operations with Text files. Currently not in use.
class Files:

	def __init__(self, name):
		self.name=name

	def load(self):
		file = open(self.name, 'r')
		tmp = file.read()
		file.close()
		return (tmp)

	def save(self, string):
		file = open(self.name, 'w')
		file.write(string)
		file.close()

#Class that handles operations with message including: initialization, padding, converting string to bits, and parsing just encrypted string.
#Instance variables: message - message itself, block - cipher block size, len - lenght of message(usefull part), vlen - lenght of vector,
#password - password used for encyption/decription (hashed), messages - array of 3 elements that include message itself, lenght and vector, 
#v - vektor, crypt - instance of AES(not used outside class), crypted_strings - crypted array messages(vector is not crypted), full_lenght - 
#lenght of message with padding 
class Message:

#Initialization. When it used without password, "Example" used as password. User password hashed. Also it adding lenght to of message to fullmessage. 
	def __init__(self,message='',password='Example'):
		self.message=message
		self.block=32
		self.vlen=16
		self.password=hashlib.sha256(password.encode('utf-8')).digest()
		#Initialization for empty message
		self.messages = [message]
		if (message == ''): 
			self.len = 0
			self.crypted_strings = [' ', ' ']
			self.messages.append ("0;")
		#and for non empty message
		else:
			self.len = len(self.message)
			self.messages.append(str(self.len)+";")

#Addition of padding to messages (message itself, lenght) and creation of vector that added without padding
	def make_block(self):
		for i in [0,1]:
			if ((len(self.messages[i]) % self.block) != 0): 
				self.messages[i] += reduce(lambda x,y: x+chr(random.randint(32,127)), (['']+ list(range ((len(self.messages[i]) % self.block), self.block))))
		self.v=reduce(lambda x,y: x+chr(random.randint(32,127)), (['']+ list(range (0, self.vlen)))) 
		self.messages.append(self.v)

#Coverting full message to bits(bits represented as normal string)
	def string_to_bits(self):
		messages = []
		#coverting vektor to bytes(need for encryption)
		v=bytes( map(lambda x: ord(x), list(self.v)) )
		#changing encoding to UTF-8, because AES working only with it. and crypting first 2 elements of messages
		for i in [0,1]:
			messages.append(bytes(self.messages[i], encoding="UTF-8"))
			#encryption
			try:
				self.crypt = AES.new(self.password, AES.MODE_CBC, v)
				messages[i] = self.crypt.encrypt(messages[i])
			except:
				print ("Something went crypting strings")
				exit_message()
		#adding vektor to array messages
		messages.append(bytes(self.v,encoding="UTF-8")  ) 
		self.crypted_strings =[]
		#representing crypted_message as binary in normal string. Also removing '0b' that added during casting
		for i in [0,1,2]:
			tmp = ((''.join (map(bin, messages[i])))[2:]).split('0b')
			#and adding extra zeros that all bytes getting represented as 8bits.
			self.crypted_strings.append(''.join((map(lambda x: x.zfill(8), tmp))))

#Parsing lenght and fullmessage from received string (used for encryption)
	def get_lenght(self,strings):
		#cutting extras
		self.v=strings[2][0:self.vlen]
		strings[1] = strings[1][0:self.block]
		#decryption
		for i in [0,1]:
			try:
				self.crypt = AES.new(self.password, AES.MODE_CBC, self.v)
				self.messages[i]=self.crypt.decrypt(strings[i]).decode()
			except:
				print ("Something went decrypting string. Most probably your passwor was wrong")
				exit_message()
		#parsing and type cast for len
		self.len = int((self.messages[1]. split(';',1))[0])
	
#Finding full lenght of message, that includes padding.(used for decryption)
	def get_full_lenght(self):
		self.full_lenght = ((self.len//self.block+1)*self.block)*8

#Class that handless Picture modifications and related picture operations. Includes: Initialization, loading and saving image, getting and setting
#least significant bit(LSB) in 1byte integer(used only inside class), getting and setting of least significant bit in Blue colour(in RGB) value of 
#particular pixel, spiral walk over pixels in picture with different operations.
#Instance variables: name - filename of picture, x,y - size of picture, pix - picture object, im - image file.
class Pictures:

#Initialization with filename
	def __init__(self, name):
		self.name=name

#Loading of picture and figuring out size.
	def load_picture (self):
		try:
			self.im = Image.open(self.name)
			self.pix = self.im.load()
			(self.x,self.y)=self.im.size
		except:
			print ("Something went wrong with opening picture.")
			exit_message()

#Saving picture as PNG file.
	def save_picture (self):
		try:
			self.im.save(self.name.rsplit('.',1)[0]+'.png',"PNG")
		except:
			print ("Something went wrong with saving picture.")
			exit_message()

#replacing of LSB(bit. and bit is char) in integer(num). Probably wouldnt be ever used outside of object.
	def add_bit(self, num, bit):
		return (int(((bin(num))[:-1]+bit), 2))

#returns LSB from integer(num). Probably wouldnt be ever used outside of object
	def get_bit(self,num):
		return (bin(num)[-1:])

#getting colour of pixel with x,y coordinates.
	def get_colour(self, x, y):
		try:
			return(self.pix[x,y])
		except:
			print ("Something wrong with picture file. It must be PNG.")
			exit_message()

#setting colour of pixel with x,y coordinates.
	def set_colour(self, x, y, r, g, b):
		try:
			self.pix[x,y]= (r,g,b)
		except:
			print ("Something wrong with picture file. It must be jpg in RGB.")
			exit_message()

#Adding new value to colours LSB of pixel (with x,y coordinates). It is suppoused to be called from spiral walk method so it have some extra
#parameters. Count - is accumulator that decreasing after every call of this method, binbit arrays of 3 character that includes new LSBs (basicly 
#'0' or '1'), and tmpstr that not really used in this method, but i had to keep it since it is called from spiral_walk method where it given 
#as param. And it must have take and return same amount of variables as getting bits. There might be more elegant way but i didnt found it so far.
	def adding_bits(self,x,y,count,binbit,tmpstr):
		if count >= 0:
			try:
				r,g,b=self.get_colour(x,y)
				try: newg = self.add_bit(g,binbit[1])
				except: newg = g
				try: newb = self.add_bit(b,binbit[2])
				except: newb = b
				self.set_colour(x,y,self.add_bit(r,binbit[0]),newg, newb)
				count -= 1
			except:
				print ("Something wrong with picture file. It must be jpg in RGB.")
				exit_message()
		return ('', count)

#Getting value of colourd LSB of pixel (with x,y coordinates). It is suppoused to be called from spiral walk method so it have some extra
#parameters. Count - is accumulator that decreasing after every call of this method, binbit array of characters that includes new LSBs (basicly 
#'0' or '1'), and tmpstr is string with bits. Method returns decreased accumulator and array of strings with just added bit.
	def getting_bits(self,x,y,count,binbit,tmpstr):
		if count >= 0:
			try:
				(r,g,b)=self.get_colour(x,y)
				tmpstr[0] += str(self.get_bit(r))
				tmpstr[1] += str(self.get_bit(g))
				tmpstr[2] += str(self.get_bit(b))
				count -= 1
			except:
				print ("Something wrong with picture file. It must be PNG.")
				exit_message()
		return (tmpstr, count)

#decoding of strings that include bits to normal strings 
	def decoding_bits(self, strings):
		return ([ bytes(list(map(lambda i: int(('0b'+strings[0][i:i+8]), 2) ,list(range (0, len(strings[0]), 8))))), 
			bytes(list(map(lambda i: int(('0b'+strings[1][i:i+8]), 2) ,list(range (0, len(strings[1]), 8))))), 
			bytes(list(map(lambda i: int(('0b'+strings[2][i:i+8]), 2) ,list(range (0, len(strings[2]), 8)))))] )

#calling of spiral walk with adding bits method. binstrings is string that include message in binary form.
	def spiral_replacement(self, binstrings):
		if (self.x*self.y)>len(binstrings):
			self.spiral_walk(0, len(binstrings[0]), [binstrings[0], binstrings[1].ljust(len(binstrings[0]),' '), binstrings[2].ljust(len(binstrings[0]),' ') ], ' ', self.adding_bits)
		else:
			print ("message is too long for your picture")
			exit_message()

#calling of spiral walk with getting bits method for 1 block of text (block is cipher block size). It should be enough to find out lenght of message.
	def spiral_getting(self, block):
		return (self.decoding_bits(self.spiral_walk(0, (block*8)-1, [' '.zfill(block*8),' '.zfill(block*8),' '.zfill(block*8)], ['','',''], self.getting_bits)))

#calling of spiral walk with getting bits method, full_lenght - is message lenght, that suppoused to be obtained after calling previous method.
	def spiral_getting2(self, full_lenght):
		if (self.x*self.y)>full_lenght:
			return (self.decoding_bits(self.spiral_walk(0, full_lenght-1, [' '.zfill(full_lenght),' '.zfill(full_lenght),' '.zfill(full_lenght)], ['','',''], self.getting_bits)))
		else:
			print ("File corrupted")
			exit_message()

#spiral_walk - method that makes main part of work. It moving over picture pixels in spiral order and perform some function (getting_bits or
#adding_bits). Movement made with 4 for cycles, even if while seems more reasonable, but it will lead to longer code and probably worse code.
#this function using recursion. Parametrs: stepnumber - always 0, though it changes during recursion, binstring - strings that represent messages
#in binary way (or empty string in case of getting_bits), tmpstr - strings that keeps bits from picture in case of getting_bits(and empty string
#in case of adding bits), and method - function that performed during movement (getting_bits or adding_bits).
	def spiral_walk(self,stepnumber,count, binstring,tmpstr, method):

		if ((self.x//2>=stepnumber) & (self.y//2>=stepnumber) & (count>-1)):
		                                                          
			for i in range (stepnumber,self.x-stepnumber): (tmpstr, count)=method(stepnumber,i,count,[binstring[0][-count], binstring[1][-count], binstring[2][-count]],tmpstr)

			if not ((self.x>self.y) & (self.y%2==0) & (self.y//2==stepnumber)):

				for i in range (stepnumber,self.y-stepnumber): (tmpstr, count)=method(i,self.x-stepnumber,count,[binstring[0][-count], binstring[1][-count], binstring[2][-count]],tmpstr)
				for i in range (self.x-stepnumber,stepnumber,-1): (tmpstr, count)=method(self.y-stepnumber,i,count,[binstring[0][-count], binstring[1][-count], binstring[2][-count]],tmpstr)

				if not ((self.x<self.y) & (self.x%2==0) & (self.x//2==stepnumber)):
					for i in range (self.y-stepnumber,stepnumber,-1): (tmpstr, count)=method(i,stepnumber,count,[binstring[0][-count], binstring[1][-count], binstring[2][-count]],tmpstr)

			stepnumber += 1
			tmpstr=self.spiral_walk(stepnumber,count,binstring,tmpstr,method)

		elif ((self.x%2==0) | (self.y%2==0)):
			if (self.x==self.y):
				(tmpstr, count)=method(stepnumber,stepnumber,count,[binstring[0][-count], binstring[1][-count], binstring[2][-count]],tmpstr)
			if ((self.x<self.y) & (self.x%2==0)):
				(tmpstr, count)=method(self.y-stepnumber+1,stepnumber-1,count,[binstring[0][-count], binstring[1][-count], binstring[2][-count]],tmpstr)
			if ((self.x>self.y) & (self.y%2==0)):
				(tmpstr, count)=method(stepnumber-1,self.x-stepnumber+1,count,[binstring[0][-count], binstring[1][-count], binstring[2][-count]],tmpstr)
		return (tmpstr)

def exit_message():
	sys.exit("""Command line syntax: to crypt crypt.py add [file] [text] [password] 
	to encrypt crypt.py get [file] [password]""")

if (len(sys.argv) < 3): exit_message()

if (sys.argv[1] == "get"):
	p1 = Pictures (sys.argv[2])
	p1.load_picture()
	print ('Picture - '+str(sys.argv[2]))
	x = Message('',sys.argv[3])
	x.get_lenght(p1.spiral_getting(x.block))
	x.get_full_lenght()
	x.get_lenght(p1.spiral_getting2(x.full_lenght))
	print ('Message Lenght - '+str(x.len))
	print ('Message - '+x.messages[0][:x.len])
	print ('Full Message - '+x.messages[0])

if (sys.argv[1] == "add"):
	x = Message (sys.argv[3], sys.argv[4])
	print ("Message - "+x.message)
	print ("Message Length - "+str(x.len))
	x.make_block()
	x.string_to_bits()
	#print ("Line ready for crypting("+str(len(x.messages[0]))+'bytes) - '+x.messages[0])
	print ("binary version("+str(len(x.crypted_strings[0]))+' bits) - '+x.crypted_strings[0])
	p = Pictures (sys.argv[2])
	p.load_picture()
	p.spiral_replacement(x.crypted_strings)
	p.save_picture()
	print ("Message added to picture.")