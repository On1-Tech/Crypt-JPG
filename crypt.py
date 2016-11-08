import random, base64, sys, hashlib
from PIL import Image
from Crypto.Cipher import AES
from functools import reduce

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

class Message:

	def __init__(self,message='',password='Example'):
		self.message=message
		self.block=32
		self.password=hashlib.sha256(password.encode('utf-8')).digest()
		if (message == ''): 
			self.len = 0
			self.fullmessage = self.crypted_string = ' '
		else:
			self.len = len(self.message)
			self.fullmessage = "len="+str(len(self.message))+";"+message

	def make_block(self):
		if ((len(self.fullmessage) % self.block) != 0): 
			self.fullmessage += reduce(lambda x,y: x+chr(random.randint(32,127)), (['']+ list(range ((len(self.fullmessage) % self.block), self.block))))

	def string_to_bits(self):
		fullmessage = bytes(self.fullmessage, encoding="UTF-8")
		self.crypt = AES.new(self.password, AES.MODE_CBC, b'This is an Test!')
		message = self.crypt.encrypt(fullmessage)
		tmp = ((''.join (map(bin, message)))[2:]).split('0b')
		self.crypted_string = ''.join((map(lambda x: x.zfill(8), tmp)))

	def get_lenght(self,string):
		self.crypt = AES.new(self.password, AES.MODE_CBC, b'This is an Test!')
		self.fullmessage=self.crypt.decrypt(string).decode()
		(self.len, self.message) = (self.fullmessage[4:]).split(';',1)
		self.len = int(self.len)
	
	def get_full_lenght(self):
		self.full_lenght = (((4+len(str(self.len))+self.len)//self.block+1)*self.block)*8

class Pictures:

	def __init__(self, name):
		self.name=name

	def load_picture (self):
		self.im = Image.open(self.name)
		self.pix = self.im.load()
		(self.x,self.y)=self.im.size

	def save_picture (self):
		self.im.save(self.name.rsplit('.',1)[0]+'.png',"PNG")

	def add_bit(self, num, bit):
		return (int(((bin(num))[:-1]+bit), 2))

	def get_bit(self,num):
		return (bin(num)[-1:])

	def get_colour(self, x, y):
		return(self.pix[x,y])

	def set_colour(self, x, y, r, g, b):
		self.pix[x,y]= (r,g,b)

	def adding_bits(self,x,y,count,binbit,tmpstr):
		if count >= 0:
			r,g,b=self.get_colour(x,y)
			self.set_colour(x,y,r,g,self.add_bit(b,binbit))
			count -= 1
		return ('', count)

	def getting_bits(self,x,y,count,binbit,tmpstr):
		if count >= 0:
			(r,g,b)=self.get_colour(x,y)
			tmpstr += str(self.get_bit(b))
			count -= 1
		return (tmpstr, count)

	def decoding_bits(self, string):
		return (bytes(list(map(lambda i: int(('0b'+string[i:i+8]), 2) ,list(range (0, len(string), 8))))))

	def spiral_replacement(self, binstring):
		self.spiral_walk(0, len(binstring), binstring, ' ', self.adding_bits)

	def spiral_getting(self, block, string):
		return (self.decoding_bits(self.spiral_walk(0, (block*8)-1, string.zfill(block*8), '', self.getting_bits)))

	def spiral_getting2(self, full_lenght, string):
		return (self.decoding_bits(self.spiral_walk(0, full_lenght-1, string.zfill(full_lenght), '', self.getting_bits)))

	def spiral_walk(self,stepnumber,count, binstring,tmpstr, method):

		if ((self.x//2>=stepnumber) & (self.y//2>=stepnumber) & (count>-1)):

			for i in range (stepnumber,self.x-stepnumber): (tmpstr, count)=method(stepnumber,i,count,binstring[-count],tmpstr)

			if not ((self.x>self.y) & (self.y%2==0) & (self.y//2==stepnumber)):

				for i in range (stepnumber,self.y-stepnumber): (tmpstr, count)=method(i,self.x-stepnumber,count,binstring[-count],tmpstr)
				for i in range (self.x-stepnumber,stepnumber,-1): (tmpstr, count)=method(self.y-stepnumber,i,count,binstring[-count],tmpstr)

				if (not (self.x<self.y) & (self.x%2==0) & (self.x//2==stepnumber)):
					for i in range (self.y-stepnumber,stepnumber,-1): (tmpstr, count)=method(i,stepnumber,count,binstring[-count],tmpstr)

			stepnumber += 1
			tmpstr=self.spiral_walk(stepnumber,count,binstring,tmpstr,method)

		elif ((self.x%2==0) | (self.y%2==0)):
			if (self.x==self.y):
				(tmpstr, count)=method(stepnumber,stepnumber,count,binstring[-count],tmpstr)
			if ((self.x<self.y) & (self.x%2==0)):
				(tmpstr, count)=method(self.y-stepnumber+1,stepnumber-1,count,binstring[-count],tmpstr)
			if ((self.x>self.y) & (self.y%2==0)):
				(tmpstr, count)=method(stepnumber-1,self.x-stepnumber+1,count,binstring[-count],tmpstr)
		return (tmpstr)

if (len(sys.argv) < 3):  
	sys.exit("""Command line syntax: to crypt crypt.py add [file] [text] [password] 
	to encrypt crypt.py get [file] [password]""")

if (sys.argv[1] == "get"):
	p1 = Pictures (sys.argv[2])
	p1.load_picture()
	print ('Picture - '+str(sys.argv[2]))
	x = Message('',sys.argv[3])
	x.get_lenght(p1.spiral_getting(x.block, x.crypted_string))
	x.get_full_lenght()
	x.get_lenght(p1.spiral_getting2(x.full_lenght, x.crypted_string))
	print ('Message Lenght - '+str(x.len))
	print ('Message - '+x.message[0:x.len])
	print ('Full Message - '+x.message)

if (sys.argv[1] == "add"):
	x = Message (sys.argv[3], sys.argv[4])
	print ("Message - "+x.message)
	print ("Message Length - "+str(x.len))
	x.make_block()
	x.string_to_bits()
	print ("Line ready for crypting("+str(len(x.fullmessage))+'bytes) - '+x.fullmessage)
	print ("binary version("+str(len(x.crypted_string))+' bits) - '+x.crypted_string)
	p = Pictures (sys.argv[2])
	p.load_picture()
	p.spiral_replacement(x.crypted_string)
	p.save_picture()
	print ("Message added to picture.")