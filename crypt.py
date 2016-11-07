import random, base64, sys, hashlib
from PIL import Image
from Crypto.Cipher import AES

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
		self.crypt = AES.new(self.password, AES.MODE_CBC, b'This is an Test!')

		if (message == ''): 
			self.len = 0
			self.fullmessage = message
			self.crypted_string ='                                                                                                                                               '
		else:
			self.len = len(self.message)
			self.fullmessage = "len="+str(len(self.message))+";"+message

	def make_block(self):
		tmp=''
		if ((len(self.fullmessage) % self.block) != 0):
			for i in range ((len(self.fullmessage) % self.block), self.block):
				tmp += chr(random.randint(32,127))
		self.fullmessage += tmp

	def string_to_bits(self):
		fullmessage = bytes(self.fullmessage, encoding="UTF-8")
		message = self.crypt.encrypt(fullmessage)
		tmp = ((''.join (map(bin, message)))[2:]).split('0b')
		for i in range (0, len(tmp)): tmp[i]=tmp[i].zfill(8)
		self.crypted_string = ''.join(tmp)

	def get_lenght(self,string):
		self.crypt = AES.new(self.password, AES.MODE_CBC, b'This is an Test!')
		self.fullmessage=self.crypt.decrypt(string).decode()
		(self.len, self.message) = (self.fullmessage[4:]).split(';',1)
		self.len = int(self.len)

class Pictures:

	def __init__(self, name):
		self.name=name

	def load_picture (self):
		self.im = Image.open(self.name)
		self.pix = self.im.load()
		(self.x,self.y)=self.im.size

	def save_picture (self):
		self.im.save(self.name.rsplit('.',1)[0]+'.png',"PNG")
	
	def int_bin (self, num):
		return (bin(num))

	def bin_int (self, num):
		return(int(num, 2))

	def add_bit(self, num, bit):
		return (self.bin_int((self.int_bin(num))[:-1]+bit))

	def get_bit(self,num):
		return (self.int_bin(num)[-1:])

	def get_colour(self, x, y):
		return(self.pix[x,y])

	def set_colour(self, x, y, r, g, b):
		self.pix[x,y]= (r,g,b)

	def adding_bits(self,x,y,stepnumber,count,binbit,tmpstr):
		if count >= 0:
			r,g,b=self.get_colour(x,y)
			self.set_colour(x,y,r,g,self.add_bit(b,binbit))
			count -= 1
		return ('', count)

	def getting_bits(self,x,y,stepnumber,count,binbit,tmpstr):
		if count >= 0:
			(r,g,b)=self.get_colour(x,y)
			count -= 1
			tmpstr += str(self.get_bit(b))
		return (tmpstr, count)

	def decoding_bits(self, string):
		tmp=[]
		for i in range (0, len(string), 8):
			tmp.append(self.bin_int('0b'+string[i:i+8]))
		return (bytes(tmp))

	def spiral_replacement(self, binstring):
		self.spiral_walk(self.x,self.y, 0, len(binstring), binstring, ' ', self.adding_bits)

	def spiral_getting(self, block, string):
		return (self.spiral_walk(self.x,self.y, 0, (block*8)-1, string.zfill(block*8), '', self.getting_bits))

	def spiral_getting2(self, full_lenght, string):
		return (self.spiral_walk(self.x,self.y, 0, full_lenght-1, string.zfill(full_lenght), '', self.getting_bits))

	def spiral_walk(self,x,y,stepnumber,count, binstring,tmpstr, method):

		if ((x//2>=stepnumber) & (y//2>=stepnumber) & (count>-1)):

			for i in range (stepnumber,x-stepnumber): (tmpstr, count)=method(stepnumber,i,stepnumber,count,binstring[-count],tmpstr)

			if not ((x>y) & (y%2==0) & (y//2==stepnumber)):

				for i in range (stepnumber,y-stepnumber): (tmpstr, count)=method(i,x-stepnumber,stepnumber,count,binstring[-count],tmpstr)

				for i in range (x-stepnumber,stepnumber,-1): (tmpstr, count)=method(y-stepnumber,i,stepnumber,count,binstring[-count],tmpstr)

				if (not (x<y) & (x%2==0) & (x//2==stepnumber)):
					for i in range (y-stepnumber,stepnumber,-1): (tmpstr, count)=method(i,stepnumber,stepnumber,count,binstring[-count],tmpstr)

			stepnumber += 1
			tmpstr=self.spiral_walk(x,y,stepnumber,count,binstring,tmpstr,method)

		elif ((x%2==0) | (y%2==0)):
			if (x==y):
				(tmpstr, count)=method(stepnumber,stepnumber,stepnumber,count,binstring[-count],tmpstr)
			if ((x<y) & (x%2==0)):
				(tmpstr, count)=method(y-stepnumber+1,stepnumber-1,stepnumber,count,binstring[-count],tmpstr)
			if ((x>y) & (y%2==0)):
				(tmpstr, count)=method(stepnumber-1,x-stepnumber+1,stepnumber,count,binstring[-count],tmpstr)
		return (tmpstr)

if (len(sys.argv) < 3):  
	sys.exit("""Command line syntax: to crypt crypt.py add [file] [text] [password] 
	to encrypt crypt.py get [file] [password]""")

if (sys.argv[1] == "get"):
	p1 = Pictures (sys.argv[2])
	p1.load_picture()
	print ('Picture - '+str(sys.argv[2]))
	x = Message('',sys.argv[3])
	x.len=32
	x.get_lenght(p1.decoding_bits(p1.spiral_getting(x.block, x.crypted_string)))
	full_lenght = (((4+len(str(x.len))+x.len)//x.block+1)*x.block)*8
	x.get_lenght(p1.decoding_bits(p1.spiral_getting2(full_lenght, x.crypted_string)))
	print ('Message Lenght - '+str(x.len))
	print ('Message - '+x.message[0:x.len])
	print ('Full Message - '+x.message)

if (sys.argv[1] == "add"):
	x = Message (sys.argv[3], sys.argv[4])
	print ("Message - "+x.message)
	print ("Message Length - "+str(x.len))
	x.make_block()
	print ("Line ready for crypting("+str(len(x.fullmessage))+'bytes) - '+x.fullmessage)
	x.string_to_bits()
	print ("binary version("+str(len(x.crypted_string))+' bits) - '+x.crypted_string)
	p = Pictures (sys.argv[2])
	p.load_picture()
	p.spiral_replacement(x.crypted_string)
	p.save_picture()
	print ("Message added to picture.")